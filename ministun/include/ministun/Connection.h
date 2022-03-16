#pragma once

#include <stddef.h>
#include <seastar/core/iostream.hh>
#include <seastar/net/api.hh>
#include <seastar/net/socket_defs.hh>
#include <ministun/Types.h>

namespace ms {
  class ServerSocket;

  class UdpServerSocket;

  class TcpServerSocket;

  class Connection {
  public:
    virtual ~Connection();

    Protocol protocol() const { return protocol_; }

    const seastar::socket_address &remote_address() const { return remote_address_; }

    virtual void shutdown() = 0;

  protected:
    Connection(Protocol protocol, ServerSocket *socket, const seastar::socket_address &remote_address);

  private:
    size_t id_;
    Protocol protocol_;
    seastar::socket_address remote_address_;
    ServerSocket *socket_;
  };

  class UdpConnection final : public Connection {
  public:
    UdpConnection(UdpServerSocket *socket, const seastar::socket_address &remote_address);

    void shutdown() override {}
  };

  class TcpConnection final : public Connection {
  public:
    TcpConnection(TcpServerSocket *socket, seastar::accept_result result);

    void shutdown() override;

    seastar::input_stream<char> read_stream;
    seastar::output_stream<char> write_stream;

  private:
    seastar::connected_socket socket_;
  };
}
