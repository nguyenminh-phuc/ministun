#include <ministun/Connection.h>
#include <boost/assert.hpp>
#include <ministun/ServerSocket.h>

using namespace seastar;

namespace ms {
  static thread_local size_t conn_id = 0;

  Connection::Connection(Protocol protocol, ServerSocket *socket, const socket_address &remote_address) :
      id_{++conn_id}, protocol_{protocol}, remote_address_{remote_address}, socket_{socket} {
    BOOST_ASSERT(socket);
    socket_->ongoing_connections_[id_] = this;
  }

  Connection::~Connection() {
    socket_->ongoing_connections_.erase(id_);
  }

  UdpConnection::UdpConnection(UdpServerSocket *socket, const socket_address &remote_address) :
      Connection{Protocol::Udp, socket, remote_address} {}

  TcpConnection::TcpConnection(TcpServerSocket *socket, accept_result result) :
      Connection{Protocol::Tcp, socket, result.remote_address} {
    socket_ = std::move(result.connection);
    read_stream = socket_.input();
    write_stream = socket_.output();
  }

  void TcpConnection::shutdown() {
    socket_.shutdown_input();
    socket_.shutdown_output();
  }
}
