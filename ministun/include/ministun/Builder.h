#pragma once

#include <stddef.h>
#include <stdint.h>
#include <map>
#include <optional>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/socket_defs.hh>
#include <ministun/ClientConfig.h>
#include <ministun/ClientCred.h>
#include <ministun/ClientSocket.h>
#include <ministun/RateLimiter.h>
#include <ministun/ServerSocket.h>
#include <ministun/Types.h>
#include <ministun/Utils.h>

namespace ms {
  /* TODO(optional): Client should use the SRV records with the lowest-numbered priority value first, and fall back to
   * records of higher priority values if the connection fails. If a service has multiple SRV records with the same
   * priority value, client should load balance them in proportion to the values of their weight fields.
   */
  class RemoteServersBuilder final {
  public:
    RemoteServersBuilder(Family family, Protocol protocol) : family_{family}, protocol_{protocol} {}

    bool add(const seastar::socket_address &address, uint16_t priority = 0, uint16_t weight = 0);

    bool add(const RemoteServer &server, uint16_t priority = 0, uint16_t weight = 0);

    seastar::future<bool> lookup_name(
        const seastar::sstring &name,
        uint16_t port = service_default_ports[Utils::to_underlying(Service::Stun)],
        Service service = Service::Stun,
        uint16_t priority = 0, uint16_t weight = 0);

    seastar::future<size_t> lookup_srv_records(const seastar::sstring &name, Service service = Service::Stun);

    std::optional<std::vector<RemoteServer>> build();

  private:
    Family family_;
    Protocol protocol_;
    std::map<uint16_t, std::vector<std::pair<RemoteServer, uint16_t>>> map_;

    bool add_new(uint16_t priority, std::pair<RemoteServer, uint16_t> new_server);
  };

  class ClientSocketBuilder final {
  public:
    struct Result final {
      seastar::shared_ptr<ClientSocket> socket;
      RemoteServer server;
    };

    ClientSocketBuilder(
        Protocol protocol,
        const seastar::socket_address &local_address, std::vector<RemoteServer> servers) :
        protocol_{protocol}, local_address_{local_address}, servers_{std::move(servers)} {
      BOOST_ASSERT(!servers_.empty());
      for (const auto &server: servers_)
        BOOST_ASSERT(local_address.family() == server.address.family());
    }

    seastar::future<std::optional<Result>> build() const;

  private:
    Protocol protocol_;
    seastar::socket_address local_address_;
    std::vector<RemoteServer> servers_;
  };

  class ClientCredBuilder final {
  public:
    ClientCredBuilder(CredentialMechanism mechanism, seastar::sstring username, std::vector<char> password) :
        mechanism_{mechanism}, username_{std::move(username)}, password_{std::move(password)} {
      BOOST_ASSERT(!username_.empty() && !password_.empty());
    }

    seastar::shared_ptr<ClientCred> build() const;

  private:
    CredentialMechanism mechanism_;
    seastar::sstring username_;
    std::vector<char> password_;
  };

  class ServerSocketBuilder final {
  public:
    ServerSocketBuilder(Protocol protocol, const seastar::socket_address &local_address) :
        protocol_{protocol}, local_address_{local_address} {}

    seastar::shared_ptr<ServerSocket> build() const;

  private:
    Protocol protocol_;
    seastar::socket_address local_address_;
  };
}
