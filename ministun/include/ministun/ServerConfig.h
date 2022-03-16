#pragma once

#include <stdlib.h>
#include <array>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/socket_defs.hh>
#include <seastar/util/log.hh>
#include <ministun/Authenticator.h>
#include <ministun/RateLimiter.h>
#include <ministun/ServerSocket.h>
#include <ministun/Types.h>

namespace ms {
  struct ConfigXml final {
    static constexpr std::array<std::string_view, 1> supported_limiters = {
        "ModuloRateLimiter"
    };

    static constexpr std::array<std::string_view, 2> supported_authenticators = {
        "StaticShortTermAuthenticator",
        "StaticLongTermAuthenticator"
    };

    static std::optional<ConfigXml> parse(const seastar::sstring &filepath);

    seastar::log_level log_level;

    struct {
      bool enabled;
      seastar::socket_address address;
    } reporter;

    struct {
      bool enabled;
      size_t rate;
      std::chrono::minutes block_timeout;
      size_t max_tracked_addresses;
    } limiter;

    struct {
      bool enabled;
      CredentialMechanism mechanism;
      std::optional<seastar::sstring> key;
      std::optional<seastar::sstring> realm;
      std::optional<SecurityFeatureSet> feature_set;
      std::optional<std::chrono::minutes> nonce_timeout;
      std::map<seastar::sstring, seastar::sstring> users;
    } authenticator;

    struct Server final {
      Server(Protocol protocol, const seastar::socket_address &address) : protocol{protocol}, address{address} {}

      Protocol protocol;
      seastar::socket_address address;
    };

    std::vector<Server> servers;
  };

  struct ServerConfig final {
    seastar::shared_ptr<ServerSocket> socket;
    std::shared_ptr<RateLimiter> limiter;
    seastar::shared_ptr<Authenticator> authenticator;
  };
}
