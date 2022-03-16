#include <stdlib.h>
#include <exception>
#include <map>
#include <memory>
#include <utility>
#include <vector>
#include <seastar/core/app-template.hh>
#include <ministun/MiniStun.h>
#include "stop_signal.hh"

namespace po = boost::program_options;
using namespace seastar;
using namespace ms;

struct Input final {
  seastar_apps_lib::stop_signal stop_signal;
  std::optional<ConfigXml> xml;
  std::shared_ptr<RateLimiter> limiter;
  lw_shared_ptr<MetricReporter> reporter;
  distributed<ShardedInstance<Authenticator>> authenticators;
  std::vector<std::unique_ptr<distributed<Server>>> servers;
};

static std::shared_ptr<RateLimiter> build_limiter(const ConfigXml &xml);

static future<bool> start_reporter(lw_shared_ptr<MetricReporter> &reporter, const ConfigXml &xml);

static future<> start_authenticators(distributed<ShardedInstance<Authenticator>> &authenticators, const ConfigXml &xml);

static future<bool> start_servers(
    std::vector<std::unique_ptr<distributed<Server>>> &ok,
    const std::shared_ptr<RateLimiter> &limiter,
    distributed<ShardedInstance<Authenticator>> &authenticators,
    const ConfigXml &xml);

static future<> stop_servers(std::vector<std::unique_ptr<distributed<Server>>> &servers);

static future<> stop_authenticators(distributed<ShardedInstance<Authenticator>> &authenticators);

static future<> stop_reporter(lw_shared_ptr<MetricReporter> &reporter);

int main(int ac, char **av) {
  app_template::config app_config;
  app_config.name = "stunserver";
  app_config.auto_handle_sigint_sigterm = false;

  log_level level;
  sstring filepath;

  app_template app{app_config};
  app.add_options()
      ("log-level", po::value<log_level>(&level)->default_value(log_level::info),
       R"(either "trace", "debug", "info", "warn" or "error")")
      ("config", po::value<sstring>(&filepath)->required(), "config filepath");

  return app.run(ac, av, [&] {
    Utils::logger().set_level(level);

    auto input = make_lw_shared<Input>();
    if (!(input->xml = ConfigXml::parse(filepath))) return make_ready_future<int>(EXIT_FAILURE);

    Utils::logger().set_level(input->xml->log_level);

    input->limiter = build_limiter(*input->xml);

    return start_reporter(input->reporter, *input->xml).then([input](bool ok) {
      if (!ok) return make_ready_future<bool>(false);
      return start_authenticators(input->authenticators, *input->xml).then([input] {
        return start_servers(input->servers, input->limiter, input->authenticators, *input->xml);
      });
    }).then([input](bool ok) {
      if (!ok) {
        MS_ERROR("Error detected");
        return make_ready_future<int>(EXIT_FAILURE);
      }

      return input->stop_signal.wait().then([&] {
        MS_INFO("Signaled");
        return EXIT_SUCCESS;
      });

    }).then([input](int result) {
      return stop_servers(input->servers).then([&] {
        return stop_authenticators(input->authenticators);
      }).then([input] {
        return stop_reporter(input->reporter);
      }).then([result] {
        return result;
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

std::shared_ptr<RateLimiter> build_limiter(const ConfigXml &xml) {
  if (!xml.limiter.enabled) return nullptr;

  return std::make_shared<ModuloRateLimiter>(
      xml.limiter.rate,
      xml.limiter.block_timeout,
      xml.limiter.max_tracked_addresses);
}

future<bool> start_reporter(lw_shared_ptr<MetricReporter> &reporter, const ConfigXml &xml) {
  if (!xml.reporter.enabled) return make_ready_future<bool>(true);

  reporter = make_lw_shared<MetricReporter>(xml.reporter.address);
  return reporter->start().then([reporter](bool started) {
    if (!started) MS_ERROR("Failed to start reporter");
    return started;
  });
}

future<> start_authenticators(distributed<ShardedInstance<Authenticator>> &authenticators, const ConfigXml &xml) {
  if (!xml.authenticator.enabled) return make_ready_future<>();

  return authenticators.start().then([&authenticators, &xml] {
    return authenticators.invoke_on_all([&xml](ShardedInstance<Authenticator> &instance) {
      std::map<sstring, std::vector<char>> users;
      for (const auto &user: xml.authenticator.users) {
        auto pair = std::make_pair(user.first, std::vector<char>{user.second.cbegin(), user.second.cend()});
        users.insert(std::move(pair));
      }

      shared_ptr<Authenticator> authenticator;
      if (xml.authenticator.mechanism == CredentialMechanism::ShortTerm) {
        authenticator = ::make_shared<StaticShortTermAuthenticator>(users);
      } else {
        std::vector<char> key{xml.authenticator.key->cbegin(), xml.authenticator.key->cend()};
        authenticator = ::make_shared<StaticLongTermAuthenticator>(
            users,
            std::move(key), *xml.authenticator.realm,
            *xml.authenticator.feature_set,
            *xml.authenticator.nonce_timeout);
      }

      instance.construct(std::move(authenticator));
    });
  });
}

future<bool> start_servers(
    std::vector<std::unique_ptr<distributed<Server>>> &servers,
    const std::shared_ptr<RateLimiter> &limiter,
    distributed<ShardedInstance<Authenticator>> &authenticators,
    const ConfigXml &xml) {
  return do_with(bool{true}, [&servers, &limiter, &authenticators, &xml](bool &ok) {
    return do_for_each(
        xml.servers.cbegin(), xml.servers.cend(),
        [&servers, &limiter, &authenticators, &ok](const ConfigXml::Server &server_xml) {
          servers.emplace_back(std::make_unique<distributed<Server>>());

          return futurize_invoke([&servers, &server_xml] {
            if (server_xml.protocol == Protocol::Udp && !engine().net().has_per_core_namespace())
              return servers.back()->start_single();
            return servers.back()->start();
          }).then([&servers, &limiter, &authenticators, &server_xml, &ok] {
            return servers.back()->invoke_on_all([&limiter, &authenticators, &server_xml, &ok](Server &server) {
              const ServerSocketBuilder builder{server_xml.protocol, server_xml.address};
              if (auto socket = builder.build()) {
                shared_ptr<Authenticator> authenticator;
                if (authenticators.local_is_initialized()) authenticator = authenticators.local().instance();

                ServerConfig config = {
                    .socket = std::move(socket),
                    .limiter = limiter,
                    .authenticator = std::move(authenticator)
                };

                if (!server.start(std::move(config))) {
                  ok = false;
                  MS_ERROR("Failed to start {} server {}", server_xml.protocol, server_xml.address);
                }
              } else {
                ok = false;
                MS_ERROR("Failed to build socket {} for {} server", server_xml.address, server_xml.protocol);
              }
            });
          });
        }).then([&ok] { return ok; });
  });
}

future<> stop_servers(std::vector<std::unique_ptr<distributed<Server>>> &servers) {
  return parallel_for_each(servers.begin(), servers.end(), [](std::unique_ptr<distributed<Server>> &server) {
    return server->stop();
  });
}

future<> stop_authenticators(distributed<ShardedInstance<Authenticator>> &authenticators) {
  return authenticators.stop();
}

future<> stop_reporter(lw_shared_ptr<MetricReporter> &reporter) {
  if (!reporter) return make_ready_future<>();
  return reporter->stop();
}
