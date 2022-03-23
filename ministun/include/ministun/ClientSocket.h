#pragma once

#include <stddef.h>
#include <chrono>
#include <memory>
#include <optional>
#include <utility>
#include <boost/assert.hpp>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/packet.hh>
#include <seastar/net/stack.hh>
#include <ministun/Buffer.h>
#include <ministun/Message.h>
#include <ministun/Types.h>

namespace ms {
  class ClientSocket {
  public:
    struct Response final {
      MessageBufferReader reader;
      Message message;
    };

    ClientSocket(
        Protocol protocol,
        const seastar::socket_address &local_address, const seastar::socket_address &remote_address) :
        opened_{}, receiving_{}, limit_{1},
        protocol_{protocol}, local_address_{local_address}, remote_address_{remote_address} {}

    virtual ~ClientSocket() {
      BOOST_ASSERT(!opened_);
    }

    Protocol protocol() const { return protocol_; }

    const seastar::socket_address &local_address() const { return local_address_; }

    const seastar::socket_address &remote_address() const { return remote_address_; }

    virtual seastar::future<> close_gracefully() = 0;

    virtual seastar::future<std::unique_ptr<Response>> send_request(const MessageBuffer &buffer) = 0;

    virtual seastar::future<bool> send_indication(const MessageBuffer &buffer) = 0;

  protected:
    bool opened_;
    bool receiving_;
    std::unique_ptr<Response> response_;
    seastar::semaphore limit_;
    seastar::condition_variable wait_response_cond_;
    seastar::condition_variable receive_response_finished_cond_;

  private:
    Protocol protocol_;
    seastar::socket_address local_address_;
    seastar::socket_address remote_address_;
  };

  class UdpClientSocket final : public ClientSocket {
  public:
    static constexpr size_t default_max_retries = 3;
    static constexpr std::chrono::milliseconds default_timeout{500};

    static std::optional<UdpClientSocket> make_channel(
        const seastar::socket_address &local_address, const seastar::socket_address &remote_address,
        size_t max_retries = default_max_retries, std::chrono::milliseconds timeout = default_timeout);

    UdpClientSocket(UdpClientSocket &&socket) noexcept:
        ClientSocket{Protocol::Udp, socket.local_address(), socket.remote_address()},
        max_retries_{socket.max_retries_}, timeout_{socket.timeout_} {
      opened_ = socket.opened_;
      channel_ = std::move(socket.channel_);

      socket.opened_ = false;
    }

    seastar::future<> close_gracefully() override;

    seastar::future<std::unique_ptr<Response>> send_request(const MessageBuffer &buffer) override;

    seastar::future<bool> send_indication(const MessageBuffer &buffer) override;

  private:
    size_t max_retries_;
    std::chrono::milliseconds timeout_;
    seastar::net::udp_channel channel_;

    UdpClientSocket(
        const seastar::socket_address &local_address, const seastar::socket_address &remote_address,
        size_t max_retries, std::chrono::milliseconds timeout) :
        ClientSocket{Protocol::Udp, local_address, remote_address},
        max_retries_{max_retries}, timeout_{timeout} {}

    seastar::future<bool> send_packet(seastar::net::packet packet);

    seastar::future<seastar::stop_iteration> send_retry(const MessageBuffer &buffer, size_t &i);

    void receive_response();
  };

  class TcpClientSocket final : public ClientSocket {
  public:
    static constexpr std::chrono::milliseconds default_timeout{1500};

    static seastar::future<std::optional<TcpClientSocket>> make_connection(
        const seastar::socket_address &local_address, const seastar::socket_address &remote_address,
        std::chrono::milliseconds timeout = default_timeout);

    TcpClientSocket(TcpClientSocket &&socket) noexcept:
        ClientSocket{Protocol::Tcp, socket.local_address(), socket.remote_address()}, timeout_{socket.timeout_} {
      opened_ = socket.opened_;
      socket_ = std::move(socket.socket_);
      connected_socket_ = std::move(socket.connected_socket_);
      read_stream_ = std::move(socket.read_stream_);
      write_stream_ = std::move(socket.write_stream_);

      socket.opened_ = false;
    }

    seastar::future<> close_gracefully() override;

    seastar::future<std::unique_ptr<Response>> send_request(const MessageBuffer &buffer) override;

    seastar::future<bool> send_indication(const MessageBuffer &buffer) override;

  private:
    std::chrono::milliseconds timeout_;
    seastar::socket socket_;
    seastar::connected_socket connected_socket_;
    seastar::input_stream<char> read_stream_;
    seastar::output_stream<char> write_stream_;

    TcpClientSocket(
        const seastar::socket_address &local_address, const seastar::socket_address &remote_address,
        std::chrono::milliseconds timeout) :
        ClientSocket{Protocol::Tcp, local_address, remote_address}, timeout_{timeout} {}

    seastar::future<bool> send_bytes(const MessageBuffer &buffer);

    seastar::future<std::optional<seastar::temporary_buffer<char>>> receive_bytes(size_t size);

    void receive_response();
  };
}
