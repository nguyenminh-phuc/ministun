#pragma once

#include <optional>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/metrics.hh>
#include <seastar/core/shared_ptr.hh>
#include <ministun/Buffer.h>
#include <ministun/ServerConfig.h>
#include <ministun/Connection.h>
#include <ministun/Message.h>

namespace ms {
  class Server final {
  public:
    struct Response final {
      Message message;
      std::optional<std::vector<char>> key;
    };

    enum class State {
      Started,
      Stopping,
      Stopped
    };

    Server();

    ~Server() {
      BOOST_ASSERT(state_ == State::Stopped);
    }

    State state() const { return state_; }

    const ServerConfig &config() const { return config_; }

    bool start(ServerConfig config);

    seastar::future<> stop();

    seastar::future<std::optional<Response>> process_request(
        const seastar::shared_ptr<Connection> &result,
        const MessageBufferReader &request_reader, const Message &request) const;

    seastar::future<> process_indication(
        [[maybe_unused]] const seastar::shared_ptr<Connection> &conn,
        [[maybe_unused]] const MessageBufferReader &indication_reader, const Message &indication) const {
      BOOST_ASSERT(indication.cls() == Class::Indication);
      return seastar::make_ready_future<>();
    }

  private:
    State state_;
    ServerConfig config_;
    seastar::metrics::metric_groups metrics_;
  };
}
