#pragma once

#include <optional>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/socket_defs.hh>
#include <ministun/ClientSocket.h>
#include <ministun/ClientCred.h>
#include <ministun/Types.h>

namespace ms {
  struct RemoteServer final {
    Service service;
    seastar::socket_address address;
    std::optional<seastar::sstring> name;
  };

  struct ClientConfig final {
    seastar::shared_ptr<ClientSocket> socket;
    RemoteServer server;
    seastar::shared_ptr<ClientCred> credential;
  };
}
