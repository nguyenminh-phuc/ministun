#pragma once

#include <stdint.h>
#include <optional>
#include <utility>
#include <variant>
#include <seastar/net/inet_address.hh>
#include <seastar/core/sstring.hh>
#include <ministun/Types.h>

namespace ms {
  struct Uri final {
    static std::optional<Uri> parse(const seastar::sstring &uri_str);

    Service service;
    std::variant<seastar::sstring, seastar::net::inet_address> host;
    uint16_t port;
  };
}
