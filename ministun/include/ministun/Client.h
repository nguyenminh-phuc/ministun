#pragma once

#include <optional>
#include <utility>
#include <boost/assert.hpp>
#include <seastar/core/semaphore.hh>
#include <ministun/ClientConfig.h>
#include <ministun/Message.h>

namespace ms {
  struct BindingResult final {
    seastar::socket_address local_address;
    seastar::socket_address mapped_address;
  };

  class Client final {
  public:
    Client(ClientConfig config) : config_{std::move(config)}, limit_{1} {
      BOOST_ASSERT(config_.socket);
    }

    seastar::future<std::optional<BindingResult>> test_binding();

    seastar::future<> close_gracefully() const;

  private:
    ClientConfig config_;
    seastar::semaphore limit_;

    seastar::future<std::optional<Message>> send_retry(const Message &request) const;
  };
}
