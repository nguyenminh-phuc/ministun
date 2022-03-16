#include <ministun/ServerConfig.h>
#include <stdint.h>
#include <exception>
#include <stdexcept>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <ministun/RateLimiter.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  std::optional<ConfigXml> ConfigXml::parse(const sstring &filepath) {
    try {
      ConfigXml xml = {
          .log_level = log_level::info,
          .reporter = {
              .enabled = false,
              .address = socket_address{static_cast<uint16_t>(9180)}
          },
          .limiter = {
              .enabled = false,
              .rate = ModuloRateLimiter::default_rate,
              .block_timeout = ModuloRateLimiter::default_blocked_timeout
          },
          .authenticator = {
              .enabled = false,
              .mechanism = CredentialMechanism::ShortTerm
          }
      };

      boost::property_tree::ptree root;
      boost::property_tree::xml_parser::read_xml(filepath, root);

      const auto &config = root.get_child("Config");

      if (auto log_level_str = config.get_optional<sstring>("LogLevel")) {
        MS_GET(log_level, Utils::log_level_from_string(*log_level_str), std::optional<ConfigXml>())
        xml.log_level = *log_level;
      }

      if (auto reporter = config.get_child_optional("MetricReporter")) {
        xml.reporter.enabled = reporter->get<bool>("Enabled", false);
        const auto ip_str = reporter->get<sstring>("Ip", "");
        const auto port = reporter->get<uint16_t>("Port", 9180);
        if (ip_str.empty()) xml.reporter.address = socket_address{port};
        else {
          MS_GET(ip, Utils::ip_from_string(ip_str), std::optional<ConfigXml>())
          xml.reporter.address = socket_address{*ip, port};
        }
      }

      if (auto limiter = config.get_child_optional("RateLimiter")) {
        const auto type = limiter->get<sstring>("Type", sstring{supported_limiters[0]});
        if (Utils::to_lower(type) != Utils::to_lower(sstring{supported_limiters[0]}))
          throw std::runtime_error(format("Limiter type {} is not supported", type));

        const auto &modulo_limiter = limiter->get_child(supported_limiters[0].data());

        const auto enabled = limiter->get<bool>("Enabled", false);

        const auto rate = modulo_limiter.get<size_t>("Rate", ModuloRateLimiter::default_rate);
        if (!rate) throw std::runtime_error("Invalid rate");

        const auto block_timeout = decltype(ModuloRateLimiter::default_blocked_timeout){modulo_limiter.get<size_t>(
            "BlockTimeout", ModuloRateLimiter::default_blocked_timeout.count())};
        if (!block_timeout.count()) throw std::runtime_error("Invalid black timeout");

        const auto max_tracked_addresses = modulo_limiter.get<size_t>(
            "MaxTrackedAddresses", ModuloRateLimiter::default_max_tracked_addresses);
        if (!max_tracked_addresses) throw std::runtime_error("Invalid maximum tracked addresses");

        xml.limiter = {
            .enabled = enabled,
            .rate = rate,
            .block_timeout = block_timeout,
            .max_tracked_addresses = max_tracked_addresses
        };
      }

      if (auto authenticator = config.get_child_optional("Authenticator")) {
        const auto type = authenticator->get<sstring>("Type", sstring{supported_authenticators[0]});
        if (Utils::to_lower(type) != Utils::to_lower(sstring{supported_authenticators[0]}) &&
            Utils::to_lower(type) != Utils::to_lower(sstring{supported_authenticators[1]}))
          throw std::runtime_error(format("Authenticator type {} is not supported", type));

        const auto enabled = authenticator->get<bool>("Enabled", false);

        CredentialMechanism mechanism = CredentialMechanism::ShortTerm;
        std::optional<sstring> key;
        std::optional<sstring> realm;
        std::optional<SecurityFeatureSet> feature_set;
        std::optional<std::chrono::minutes> nonce_timeout;
        std::map<sstring, sstring> users;

        if (Utils::to_lower(type) == Utils::to_lower(sstring{supported_authenticators[1]})) {
          mechanism = CredentialMechanism::LongTerm;

          const auto &long_term_authenticator = authenticator->get_child(supported_authenticators[1].data());

          if (auto key_opt = long_term_authenticator.get_optional<sstring>("Key")) key = std::move(*key_opt);
          else throw std::runtime_error("Failed to get key");

          if (auto realm_opt = long_term_authenticator.get_optional<sstring>("Realm")) realm = std::move(*realm_opt);
          else throw std::runtime_error("Failed to get realm");

          const auto &security_features = long_term_authenticator.get_child("SecurityFeatures");
          feature_set = SecurityFeatureSet{
              .password_algorithms = security_features.get<bool>("PasswordAlgorithms", true),
              .username_anonymity = security_features.get<bool>("UsernameAnonymity", true)
          };

          nonce_timeout =
              decltype(LongTermAuthenticator::default_nonce_timeout){long_term_authenticator.get<size_t>(
                  "NonceTimeout", LongTermAuthenticator::default_nonce_timeout.count())};
          if (!nonce_timeout->count()) throw std::runtime_error("Invalid nonce timeout");
        }

        const auto &users_pt = authenticator->get_child("Users");
        if (users_pt.empty()) throw std::runtime_error("Failed to get users");

        for (const auto &user: users_pt) {
          sstring username;
          if (auto username_opt = user.second.get_optional<sstring>("Username")) username = std::move(*username_opt);
          else throw std::runtime_error("Failed to get username");

          sstring password;
          if (auto password_opt = user.second.get_optional<sstring>("Password")) password = std::move(*password_opt);
          else throw std::runtime_error("Failed to get password");

          users.insert(std::make_pair(username, password));
        }

        xml.authenticator = {
            .enabled = enabled,
            .mechanism = mechanism,
            .key = std::move(key),
            .realm = std::move(realm),
            .feature_set = feature_set,
            .nonce_timeout = nonce_timeout,
            .users = std::move(users)
        };
      }

      const auto &servers = config.get_child("Servers");
      if (servers.empty()) throw std::runtime_error("Failed to get servers");

      for (const auto &server: servers) {
        const auto family_str = server.second.get<sstring>("Family", "4");
        MS_GET(family, family_from_string(family_str), std::optional<ConfigXml>())
        const auto protocol_str =
            server.second.get<sstring>("Protocol", protocol_strs[Utils::to_underlying(Protocol::Udp)].data());
        MS_GET(protocol, protocol_from_string(Utils::to_lower(protocol_str)), std::optional<ConfigXml>())
        const auto ip_str = server.second.get<sstring>("Ip", "");
        const auto port =
            server.second.get<uint16_t>("Port", service_default_ports[Utils::to_underlying(Service::Stun)]);
        socket_address address;
        if (ip_str.empty()) {
          if (*family == Family::Inet) address = socket_address{ipv4_addr{port}};
          else address = socket_address{ipv6_addr{port}};
        } else {
          MS_GET(ip, Utils::ip_from_string(ip_str), std::optional<ConfigXml>())
          if (static_cast<Family>(ip->in_family()) != family) return std::optional<ConfigXml>();
          address = socket_address{*ip, port};
        }

        xml.servers.emplace_back(*protocol, address);
      }

      return xml;
    } catch (const std::exception &e) {
      MS_DEBUG("Failed to parse XML file {}. Exception caught: {}", filepath, e.what());
      return {};
    }
  }
}
