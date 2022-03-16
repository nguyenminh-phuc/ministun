#pragma once

#include <stdint.h>
#include <time.h>
#include <array>
#include <iostream>
#include <optional>
#include <type_traits>
#include <seastar/core/sstring.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/socket_defs.hh>
#include <seastar/util/log.hh>
#include <ministun/Types.h>

#define MS_STR_IMPL(x) #x
#define MS_STR(x) MS_STR_IMPL(x)

//#define MS_FUNC __func__
#define MS_FUNC __PRETTY_FUNCTION__ // contains the signature of the function as well as its bare name

#define MS_TRACE(fmt, ...) ms::Utils::logger().trace("[{}:" MS_STR(__LINE__) "] " fmt, MS_FUNC __VA_OPT__(,) __VA_ARGS__)
#define MS_DEBUG(fmt, ...) ms::Utils::logger().debug("[{}:" MS_STR(__LINE__) "] " fmt, MS_FUNC __VA_OPT__(,) __VA_ARGS__)
#define MS_INFO(fmt, ...) ms::Utils::logger().info("[{}:" MS_STR(__LINE__) "] " fmt, MS_FUNC __VA_OPT__(,) __VA_ARGS__)
#define MS_WARN(fmt, ...) ms::Utils::logger().warn("[{}:" MS_STR(__LINE__) "] " fmt, MS_FUNC __VA_OPT__(,) __VA_ARGS__)
#define MS_ERROR(fmt, ...) ms::Utils::logger().error("[{}:" MS_STR(__LINE__) "] " fmt, MS_FUNC __VA_OPT__(,) __VA_ARGS__)

#define MS_GET0(var, expr)           \
  auto var = (expr);                 \
  if (!var) {                        \
    MS_TRACE("Failed to get " #var); \
    return;                          \
  }

#define MS_GET(var, expr, ret_value_if_false) \
  auto var = (expr);                          \
  if (!var) {                                 \
    MS_TRACE("Failed to get " #var);          \
    return (ret_value_if_false);              \
  }

#define MS_GETREF(var, expr, ret_value_if_false) \
  auto &var = (expr);                            \
  if (!var) {                                    \
    MS_TRACE("Failed to get ref " #var);         \
    return (ret_value_if_false);                 \
  }

namespace ms {
  std::istream &operator>>(std::istream &in, Family &family);

  std::ostream &operator<<(std::ostream &os, Family family);

  std::istream &operator>>(std::istream &in, Protocol &protocol);

  std::ostream &operator<<(std::ostream &os, Protocol protocol);

  std::istream &operator>>(std::istream &in, CredentialMechanism &mechanism);

  std::ostream &operator<<(std::ostream &os, CredentialMechanism mechanism);

  class Utils final {
  public:
    static seastar::logger &logger() {
      static seastar::logger logger{"ministun"};
      return logger;
    }

    /* TODO(optional): the transaction ID MUST be uniformly and randomly chosen from the interval 0 .. 2**96-1 and MUST
     * be cryptographically random.
     */
    static char random();

    static std::optional<uint16_t> u16_from_string(const seastar::sstring &string);

    static std::optional<time_t> time_from_string(const seastar::sstring &string);

    static std::optional<seastar::net::inet_address> ip_from_string(const seastar::sstring &string);

    static std::optional<seastar::log_level> log_level_from_string(const seastar::sstring &string);

    static seastar::sstring sha1_to_string(const std::array<char, 20> &hash);

    template<typename E>
    static constexpr auto to_underlying(E e) noexcept {
      return static_cast<std::underlying_type_t<E>>(e);
    }

    static seastar::sstring to_lower(const seastar::sstring &string);

    Utils() = delete;
  };
}
