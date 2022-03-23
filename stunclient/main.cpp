#include <stdlib.h>
#include <exception>
#include <optional>
#include <utility>
#include <variant>
#include <seastar/core/app-template.hh>
#include <ministun/MiniStun.h>

namespace po = boost::program_options;
using namespace seastar;
using namespace ms;

struct Input final {
  shared_ptr<ClientCred> credential;
  std::optional<Uri> uri;
};

static shared_ptr<ClientCred>
build_credential(CredentialMechanism mechanism, const sstring &username, const sstring &password);

static std::optional<Uri> build_uri(const sstring &uri_str);

static future<std::optional<std::vector<RemoteServer>>>
build_servers(Family family, Protocol protocol, const Uri &uri);

static future<std::optional<ClientSocketBuilder::Result>> build_socket(
    Family family, Protocol protocol,
    const sstring &ip_str, uint16_t port,
    std::vector<RemoteServer> servers);

int main(int ac, char **av) {
  app_template::config config;
  config.name = "stunclient";

  log_level level;
  Family family;
  Protocol protocol;
  CredentialMechanism mechanism;
  sstring username;
  sstring password;
  sstring local_ip_str;
  uint16_t local_port;
  sstring uri_str;

  app_template app{config};
  app.add_options()
      ("log-level", po::value<log_level>(&level)->default_value(log_level::info),
       R"(either "trace", "debug", "info", "warn" or "error")")
      ("family", po::value<Family>(&family)->default_value(Family::Inet),
       R"(either "4" or "6" to specify the usage of INET or INET6)")
      ("protocol", po::value<Protocol>(&protocol)->default_value(Protocol::Udp), R"(either "udp" or "tcp")")
      ("mechanism", po::value<CredentialMechanism>(&mechanism), R"(either "ShortTerm" or "LongTerm")")
      ("username", po::value<sstring>(&username), "username")
      ("username", po::value<sstring>(&password), "password")
      ("local-ip", po::value<sstring>(&local_ip_str), "local IP")
      ("local-port", po::value<uint16_t>(&local_port), "local port")
      ("server", po::value<sstring>(&uri_str)->required(), "server URI");

  return app.run(ac, av, [&] {
    Utils::logger().set_level(level);

    const auto &configuration = app.configuration();
    auto input = make_lw_shared<Input>();

    return futurize_invoke([&, input] {
      if (configuration.count("mechanism")) {
        if (!(input->credential = build_credential(mechanism, username, password)))
          return make_ready_future<lw_shared_ptr<Client>>();
      }

      input->uri = build_uri(uri_str);
      if (!input->uri) return make_ready_future<lw_shared_ptr<Client>>();

      return build_servers(family, protocol, *input->uri)
          .then([&, input](std::optional<std::vector<RemoteServer>> servers) {
            if (!servers) {
              MS_ERROR("Failed to build remote server list");
              return make_ready_future<lw_shared_ptr<Client>>();
            }

            return build_socket(family, protocol, local_ip_str, local_port, std::move(*servers))
                .then([input](std::optional<ClientSocketBuilder::Result> result) {
                  if (!result) {
                    MS_ERROR("Failed to build socket");
                    return lw_shared_ptr<Client>{};
                  }

                  ClientConfig config{
                      .socket = std::move(result->socket),
                      .server = std::move(result->server),
                      .credential = input->credential
                  };

                  return make_lw_shared<Client>(config);
                });
          });
    }).then([](const lw_shared_ptr<Client> &client) {
      if (!client) return make_ready_future<int>(EXIT_FAILURE);

      return client->test_binding().then([client](std::optional<BindingResult> result) {
        return client->close_gracefully().then([client, result] {
          if (!result) return EXIT_FAILURE;

          MS_INFO("\nLocal address: {}\nMapped address: {}", result->local_address, result->mapped_address);
          return EXIT_SUCCESS;
        });
      });
    }).then_wrapped([](future<int> f) {
      try {
        return f.get();
      } catch (const std::exception &e) {
        MS_ERROR("Unhandled exception caught: {}", e.what());
        return EXIT_FAILURE;
      } catch (...) {
        MS_ERROR("Unhandled exception caught");
        return EXIT_FAILURE;
      }
    });
  });
}

shared_ptr<ClientCred>
build_credential(CredentialMechanism mechanism, const sstring &username, const sstring &password) {
  if (username.empty()) {
    MS_ERROR("Username could not be empty");
    return nullptr;
  }
  if (password.empty()) {
    MS_ERROR("Password could not be empty");
    return nullptr;
  }

  std::vector<char> password_vec{password.cbegin(), password.cend()};
  ClientCredBuilder cred_builder{mechanism, username, std::move(password_vec)};
  return cred_builder.build();
}

std::optional<Uri> build_uri(const sstring &uri_str) {
  MS_GET(uri, Uri::parse(uri_str), std::nullopt)

  if (uri->service == Service::Stuns) {
    if (auto ip = std::get_if<net::inet_address>(&uri->host)) MS_ERROR("Stuns URI could not contain IP {}", *ip);
    MS_ERROR("Stuns service is not supported");
    return {};
  }

  return uri;
}

future<std::optional<std::vector<RemoteServer>>>
build_servers(Family family, Protocol protocol, const Uri &uri) {
  auto builder = make_lw_shared<RemoteServersBuilder>(family, protocol);

  return futurize_invoke([&uri, builder] {
    if (auto name = std::get_if<sstring>(&uri.host)) {
      return builder->lookup_srv_records(*name, uri.service).then([&uri, builder, name](size_t count) {
        if (count) return make_ready_future<bool>(true);
        return builder->lookup_name(*name, uri.port);
      });
    } else {
      const socket_address address{std::get<net::inet_address>(uri.host), uri.port};
      return make_ready_future<bool>(builder->add(address));
    }
  }).then([builder](bool ok) {
    if (!ok) return std::optional<std::vector<RemoteServer>>{};

    return builder->build();
  });
}

future<std::optional<ClientSocketBuilder::Result>> build_socket(
    Family family, Protocol protocol,
    const sstring &ip_str, uint16_t port,
    std::vector<RemoteServer> servers) {
  socket_address address;
  if (family == Family::Inet) address = ipv4_addr{};
  else address = ipv6_addr{};

  if (!ip_str.empty() || port) {
    if (ip_str.empty()) {
      if (family == Family::Inet) address = socket_address{ipv4_addr{port}};
      else address = socket_address{ipv6_addr{port}};
    } else {
      const auto ip = Utils::ip_from_string(ip_str);
      if (!ip || static_cast<Family>(ip->in_family()) != family)
        return make_ready_future<std::optional<ClientSocketBuilder::Result>>();
      address = socket_address{*ip, port};
    }
  }

  auto builder = make_lw_shared<ClientSocketBuilder>(protocol, address, std::move(servers));
  return builder->build().then([builder](std::optional<ClientSocketBuilder::Result> result) {
    return result;
  });
}
