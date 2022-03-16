#include <ministun/Builder.h>
#include <algorithm>
#include <deque>
#include <stdexcept>
#include <seastar/core/do_with.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/print.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/inet_address.hh>

using namespace seastar;

namespace ms {
  static sstring get_full_form(Protocol protocol, Service service, const sstring &name) {
    const auto protocol_str = protocol_strs[Utils::to_underlying(protocol)];
    const auto service_str = service_strs[Utils::to_underlying(service)];
    return format("_{}._{}.{}", service_str, protocol_str, name);
  }

  static future<std::optional<net::inet_address>> resolve_name(const sstring &name, Family family) {
    MS_DEBUG("Finding {} IP", name);
    return do_with(sstring{name}, [family](const sstring &name) {
      return net::dns::resolve_name(name, static_cast<net::inet_address::family>(family))
          .then_wrapped([&name](future<net::inet_address> f) {
            try {
              const net::inet_address ip{f.get()};
              MS_DEBUG("{} IP found: {}", name, ip);
              return std::make_optional(ip);
            } catch (const std::system_error &e) {
              MS_WARN("Failed to find {} IP. Exception system_error caught, code {}: {}", name, e.code(), e.what());
              return std::optional<net::inet_address>{};
            }
          });
    });
  }

  bool RemoteServersBuilder::add(const socket_address &address, uint16_t priority, uint16_t weight) {
    RemoteServer server{Service::Stun, address, {}};
    return add_new(priority, std::make_pair(std::move(server), weight));
  }

  bool RemoteServersBuilder::add(const RemoteServer &server, uint16_t priority, uint16_t weight) {
    return add_new(priority, std::make_pair(server, weight));
  }

  future<bool> RemoteServersBuilder::lookup_name(
      const sstring &name, uint16_t port,
      Service service,
      uint16_t priority, uint16_t weight) {
    return do_with(sstring{name}, [this, port, service, priority, weight](sstring &name) {
      return resolve_name(name, family_)
          .then([this, &name, port, service, priority, weight](std::optional<net::inet_address> ip) {
            if (!ip) return false;
            RemoteServer new_server{service, socket_address{*ip, port}, std::move(name)};
            return add_new(priority, std::make_pair(std::move(new_server), weight));
          });
    });
  }

  future<size_t> RemoteServersBuilder::lookup_srv_records(const sstring &name, Service service) {
    const auto srv_protocol = protocol_ == Protocol::Udp ?
                              net::dns_resolver::srv_proto::udp : net::dns_resolver::srv_proto::tcp;

    MS_DEBUG("Finding {} SRV records", get_full_form(protocol_, service, name));
    return do_with(
        sstring{name}, std::vector<net::srv_record>{}, size_t{},
        [this, srv_protocol, service](const sstring &name, std::vector<net::srv_record> &records, size_t &count) {
          return net::dns::get_srv_records(srv_protocol, sstring{service_strs[Utils::to_underlying(service)]}, name)
              .then_wrapped([this, service, &name, &records, &count](future<std::vector<net::srv_record>> f) mutable {
                try {
                  records = f.get();
                  if (records.empty()) {
                    MS_DEBUG("No {} SRV record found", get_full_form(protocol_, service, name));
                    return make_ready_future<>();
                  }

                  MS_DEBUG("{} {} SRV records found", records.size(), get_full_form(protocol_, service, name));
                  return parallel_for_each(
                      records.cbegin(), records.cend(),
                      [this, service, &count](const net::srv_record &record) {
                        return do_with(net::srv_record{record}, [this, service, &count](const net::srv_record &record) {
                          return resolve_name(record.target, family_)
                              .then([this, &record, service, &count](std::optional<net::inet_address> ip) {
                                if (!ip) return;

                                RemoteServer new_server{service, socket_address{*ip, record.port}, record.target};
                                if (add_new(record.priority, std::make_pair(std::move(new_server), record.weight)))
                                  ++count;
                              });
                        });
                      });
                } catch (const std::system_error &e) {
                  MS_WARN("Failed to find {} SRV records. Exception system_error caught, code {}: {}",
                          get_full_form(protocol_, service, name), e.code(), e.what());
                  return make_ready_future<>();
                }
              }).then([&count] { return count; });
        });
  }

  std::optional<std::vector<RemoteServer>> RemoteServersBuilder::build() {
    if (map_.empty()) return {};

    std::vector<RemoteServer> remote_servers;
    for (const auto &servers: map_) {
      auto sorted_servers = servers.second;
      std::sort(
          sorted_servers.begin(), sorted_servers.end(),
          [](const std::pair<RemoteServer, uint16_t> &a, const std::pair<RemoteServer, uint16_t> &b) {
            return a.second > b.second;
          });

      for (auto &server: sorted_servers)
        remote_servers.emplace_back(std::move(server.first));
    }

    return remote_servers;
  }

  bool RemoteServersBuilder::add_new(uint16_t priority, std::pair<RemoteServer, uint16_t> new_server) {
    for (const auto &server: map_[priority]) {
      if (server.first.address == new_server.first.address && server.second == new_server.second)
        return false;
    }

    map_[priority].emplace_back(std::move(new_server));
    return true;
  }

  future<std::optional<ClientSocketBuilder::Result>> ClientSocketBuilder::build() const {
    if (protocol_ == Protocol::Udp) {
      auto socket = UdpClientSocket::make_channel(local_address_, servers_.front().address);
      if (!socket) return make_ready_future<std::optional<Result>>();
      Result result{
          .socket = make_shared(std::move(*socket)),
          .server = servers_.front()
      };
      return make_ready_future<std::optional<Result>>(std::move(result));
    } else {
      return do_with(
          std::deque<RemoteServer>{servers_.cbegin(), servers_.cend()}, std::optional<Result>{},
          [this](std::deque<RemoteServer> &servers, std::optional<Result> &result) {
            return repeat([this, &servers, &result] {
              if (servers.empty()) return make_ready_future<stop_iteration>(stop_iteration::yes);

              auto server = servers.front();
              servers.pop_front();
              return do_with(RemoteServer{std::move(server)}, [this, &result](RemoteServer &server) {
                return TcpClientSocket::make_connection(local_address_, server.address)
                    .then([&result, &server](std::optional<TcpClientSocket> socket) {
                      if (!socket) return stop_iteration::no;

                      Result value{
                          .socket = make_shared(std::move(*socket)),
                          .server = std::move(server)
                      };
                      result = std::make_optional(std::move(value));
                      return stop_iteration::yes;
                    });
              });
            }).then([&result] {
              auto nrvo{std::move(result)};
              return nrvo;
            });
          });
    }
  }

  shared_ptr<ClientCred> ClientCredBuilder::build() const {
    if (mechanism_ == CredentialMechanism::ShortTerm) return ::make_shared<ShortTermClientCred>(username_, password_);
    else return ::make_shared<LongTermClientCred>(username_, password_);
  }

  shared_ptr<ServerSocket> ServerSocketBuilder::build() const {
    if (protocol_ == Protocol::Udp) return UdpServerSocket::create(local_address_);
    else return TcpServerSocket::create(local_address_);
  }
}
