#pragma once

#include <stddef.h>
#include <map>
#include <utility>
#include <boost/assert.hpp>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/lowres_clock.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/api.hh>
#include <seastar/net/packet.hh>
#include <seastar/net/socket_defs.hh>
#include <ministun/Connection.h>
#include <ministun/Types.h>

namespace ms {
  class Server;

  class ServerSocket {
    friend class Connection;

  public:
    enum class State {
      Started,
      Stopping,
      Stopped
    };

    ServerSocket(Protocol protocol, const seastar::socket_address &local_address);

    virtual ~ServerSocket() {
      BOOST_ASSERT(ongoing_connections_.empty());
    }

    Protocol protocol() const { return protocol_; }

    State state() const { return state_; }

    bool accepting() const { return accepting_; }

    size_t accepted_connections() const { return accepted_connections_; }

    size_t valid_stun_connections() const { return valid_stun_connections_; }

    size_t ongoing_connections() const { return ongoing_connections_.size(); }

    const seastar::socket_address &local_address() const { return local_address_; }

    bool start(const Server *server);

    seastar::future<> stop();

  protected:
    const Server *server_;
    bool accepting_;
    size_t accepted_connections_;
    size_t valid_stun_connections_;
    seastar::condition_variable stop_cond_;

    void signal_task_started() { ++running_tasks_; }

    void signal_task_stopped();

    virtual void accept_async() = 0;

    virtual void shutdown() = 0;

  private:
    Protocol protocol_;
    State state_;
    bool startable_;
    std::map<size_t, Connection *> ongoing_connections_;
    seastar::socket_address local_address_;
    size_t running_tasks_;
    seastar::timer<seastar::lowres_clock> reset_timer_;
  };

  class UdpServerSocket final : public ServerSocket {
  public:
    static seastar::shared_ptr<UdpServerSocket> create(const seastar::socket_address &address);

    UdpServerSocket(seastar::net::udp_channel channel) :
        ServerSocket{Protocol::Udp, channel.local_address()}, channel_{std::move(channel)} {}

  private:
    seastar::net::udp_channel channel_;

    void accept_async() override;

    void shutdown() override;

    void receive_request_async(
        const seastar::shared_ptr<UdpConnection> &conn,
        seastar::temporary_buffer<char> request_buffer);

    seastar::future<>
    send_response(const seastar::shared_ptr<UdpConnection> &conn, seastar::temporary_buffer<char> response_buffer);
  };

  class TcpServerSocket final : public ServerSocket {
    friend class TcpConnection;

  public:
    static seastar::shared_ptr<TcpServerSocket> create(const seastar::socket_address &address);

    TcpServerSocket(seastar::server_socket listen_socket) :
        ServerSocket{Protocol::Tcp, listen_socket.local_address()},
        listen_socket_{std::move(listen_socket)} {}

  private:
    seastar::server_socket listen_socket_;

    static seastar::future<> close(const seastar::shared_ptr<TcpConnection> &conn);

    static seastar::future<std::optional<seastar::temporary_buffer<char>>>
    receive_bytes(const seastar::shared_ptr<TcpConnection> &conn, size_t size);

    static seastar::future<>
    send_response(const seastar::shared_ptr<TcpConnection> &conn, seastar::temporary_buffer<char> response_buffer);

    void accept_async() override;

    void shutdown() override;

    void receive_request_async(const seastar::shared_ptr<TcpConnection> &conn);
  };
}
