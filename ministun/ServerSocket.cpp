#include <ministun/ServerSocket.h>
#include <exception>
#include <seastar/core/loop.hh>
#include <seastar/core/seastar.hh>
#include <seastar/net/packet-data-source.hh>
#include <ministun/Buffer.h>
#include <ministun/Message.h>
#include <ministun/Server.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  ServerSocket::ServerSocket(Protocol protocol, const socket_address &local_address) :
      server_{}, accepting_{}, accepted_connections_{}, valid_stun_connections_{}, protocol_{protocol},
      state_{State::Stopped}, startable_{true}, local_address_{local_address}, running_tasks_{} {
    BOOST_ASSERT(server_);

    reset_timer_.set_callback([this] {
      accepted_connections_ = 0;
      valid_stun_connections_ = 0;
    });
    reset_timer_.arm_periodic(std::chrono::days{1});
  }

  void ServerSocket::signal_task_stopped() {
    --running_tasks_;
    if (!running_tasks_) stop_cond_.signal();
  }

  bool ServerSocket::start(const Server *server) {
    if (!startable_ || state_ != State::Stopped) return false;
    BOOST_VERIFY(server_ = server);

    state_ = State::Started;
    accept_async();

    return true;
  }

  future<> ServerSocket::stop() {
    if (state_ != State::Started) return make_ready_future<>();

    state_ = State::Stopping;
    startable_ = false;

    shutdown();
    for (const auto &conn: ongoing_connections_) conn.second->shutdown();

    return repeat([this] {
      if (!running_tasks_) return make_ready_future<stop_iteration>(stop_iteration::yes);
      return stop_cond_.wait().then([] { return stop_iteration::no; });
    }).then([this] {
      state_ = State::Stopped;
    });
  }

  shared_ptr<UdpServerSocket> UdpServerSocket::create(const socket_address &address) {
    try {
      auto channel = make_udp_channel(address);
      return make_shared<UdpServerSocket>(std::move(channel));
    } catch (const std::exception &e) {
      MS_ERROR("Failed to make UDP channel {}. Exception caught: {}", address, e.what());
      return nullptr;
    }
  }

  void UdpServerSocket::accept_async() {
    accepting_ = true;
    signal_task_started();
    (void) keep_doing([this] {
      return channel_.receive().then([this](net::udp_datagram dgram) {
        ++accepted_connections_;
        if (server_->config().limiter && !server_->config().limiter->permit(dgram.get_src().addr())) return;

        auto &request_packet = dgram.get_data();
        if (request_packet.len() < header_length || request_packet.len() > max_message_length) return;

        const auto conn = make_shared<UdpConnection>(this, dgram.get_src());
        temporary_buffer<char> request_buffer{net::packet_data_source(std::move(request_packet)).get().get()};
        receive_request_async(conn, std::move(request_buffer));
      });
    }).handle_exception_type([](const std::exception &e) {
      MS_WARN("Failed to receive UDP packets. Exception caught: {}", e.what());
    }).finally([this] {
      accepting_ = false;
      signal_task_stopped();
    });
  }

  void UdpServerSocket::shutdown() {
    channel_.shutdown_input();
    channel_.shutdown_output();
  }

  void
  UdpServerSocket::receive_request_async(const shared_ptr<UdpConnection> &conn, temporary_buffer<char> request_buffer) {
    signal_task_started();
    (void) do_with(
        MessageBufferReader{request_buffer},
        [this, conn](MessageBufferReader &request_reader) {
          auto request = Message::parse(request_reader);
          if (!request || (request->cls() != Class::Request && request->cls() != Class::Indication))
            return make_ready_future<>();
          ++valid_stun_connections_;

          return do_with(
              Message{std::move(*request)},
              [this, conn, &request_reader](const Message &request) {
                if (request.cls() == Class::Request) {
                  return server_->process_request(conn, request_reader, request)
                      .then([this, conn](std::optional<Server::Response> response) {
                        if (!response) return make_ready_future<>();

                        MessageBufferWriter response_writer{response->message.id()};
                        if (response->key) response_writer.set_key(*response->key);

                        if (!response->message.serialize(response_writer)) return make_ready_future<>();

                        temporary_buffer<char> response_buffer{response_writer.data(), response_writer.current_size()};
                        return send_response(conn, std::move(response_buffer));
                      });
                } else return server_->process_indication(conn, request_reader, request);
              });
        }).finally([this] {
      signal_task_stopped();
    });
  }

  future<>
  UdpServerSocket::send_response(const shared_ptr<UdpConnection> &conn, temporary_buffer<char> response_buffer) {
    net::packet packet{std::move(response_buffer)};
    const auto size = packet.len();

    return channel_.send(conn->remote_address(), std::move(packet)).then_wrapped([conn, size](future<> f) {
      try {
        f.get();
        MS_DEBUG("Sent UDP packet ({} bytes) to address {}", size, conn->remote_address());
      } catch (const std::exception &e) {
        MS_WARN("Failed to send UDP packet ({} bytes) to address {}. Exception caught: {}",
                size, conn->remote_address(), e.what());
      }
    });
  }

  shared_ptr<TcpServerSocket> TcpServerSocket::create(const socket_address &address) {
    try {
      listen_options options;
      options.reuse_address = true;
      auto socket = listen(address, options);
      return make_shared<TcpServerSocket>(std::move(socket));
    } catch (const std::exception &e) {
      MS_ERROR("Failed to listen on {}. Exception caught: {}", address, e.what());
      return nullptr;
    }
  }

  future<> TcpServerSocket::close(const shared_ptr<TcpConnection> &conn) {
    return conn->write_stream.close().then_wrapped([conn](future<> f) {
      try {
        f.get();
      } catch (const std::exception &e) {
        MS_WARN("Failed to close connection. Exception caught: {}", e.what());
      }
    });
  }

  future<std::optional<temporary_buffer<char>>>
  TcpServerSocket::receive_bytes(const shared_ptr<TcpConnection> &conn, size_t size) {
    return conn->read_stream.read_exactly(size).then_wrapped([conn, size](future<temporary_buffer<char>> f) {
      try {
        temporary_buffer<char> buffer{f.get()};

        if (buffer.size() < size) {
          MS_DEBUG("Expected {} bytes, received {} bytes from address {}", size, buffer.size(), conn->remote_address());
          return std::optional<temporary_buffer<char>>{};
        }

        return std::make_optional(std::move(buffer));
      } catch (const std::exception &e) {
        MS_WARN("Failed to receive bytes from address {}. Exception caught: {}", conn->remote_address(), e.what());
        return std::optional<temporary_buffer<char>>{};
      }
    });
  }


  future<>
  TcpServerSocket::send_response(const shared_ptr<TcpConnection> &conn, temporary_buffer<char> response_buffer) {
    const auto size = response_buffer.size();
    return conn->write_stream.write(std::move(response_buffer)).then([conn] {
      return conn->write_stream.flush();
    }).then_wrapped([conn, size](future<> f) {
      try {
        f.get();
        MS_DEBUG("Sent {} bytes to address {}", size, conn->remote_address());
        return close(conn);
      } catch (const std::exception &e) {
        MS_WARN("Failed to send {} bytes to address {}. Exception caught: {}", conn->remote_address(), size, e.what());
        return make_ready_future<>();
      }
    });
  }

  void TcpServerSocket::accept_async() {
    accepting_ = true;
    signal_task_started();
    (void) keep_doing([this] {
      return listen_socket_.accept().then([this](accept_result result) {
        ++accepted_connections_;
        if (server_->config().limiter && !server_->config().limiter->permit(result.remote_address.addr())) return;

        const auto conn = make_shared<TcpConnection>(this, std::move(result));
        receive_request_async(conn);
      });
    }).handle_exception_type([](const std::exception &e) {
      MS_WARN("Failed to accept connection. Exception caught: {}", e.what());
    }).finally([this] {
      accepting_ = false;
      signal_task_stopped();
    });
  }

  void TcpServerSocket::shutdown() {
    listen_socket_.abort_accept();
  }

  void TcpServerSocket::receive_request_async(const shared_ptr<TcpConnection> &conn) {
    signal_task_started();
    (void) do_with(
        std::optional<MessageBufferReader>{},
        [this, conn](std::optional<MessageBufferReader> &request_reader) {
          return receive_bytes(conn, header_length)
              .then([conn, &request_reader](std::optional<temporary_buffer<char>> header_buffer) {
                if (!header_buffer) return make_ready_future<std::optional<Message>>();

                BufferReader header_reader{*header_buffer};
                MS_GET(pair, Header::parse(header_reader), make_ready_future<std::optional<Message>>())
                const auto header = pair->first;
                const auto body_length = pair->second;

                if (!body_length) return make_ready_future<std::optional<Message>>(Message{header});

                return receive_bytes(conn, body_length)
                    .then([&request_reader, header_buffer = std::move(*header_buffer), header, body_length]
                              (std::optional<temporary_buffer<char>> body_buffer) mutable {
                      if (!body_buffer) return std::optional<Message>{};
                      request_reader.emplace(MessageBufferReader{header_buffer, header.id(), *body_buffer});
                      MS_GET(body, Body::parse(*request_reader, body_length), std::optional<Message>{})

                      return std::make_optional<Message>(header, std::move(*body));
                    });
              }).then([this, conn, &request_reader](std::optional<Message> request) {
            if (!request || (request->cls() != Class::Request && request->cls() != Class::Indication))
              return make_ready_future<>();
            ++valid_stun_connections_;

            return do_with(Message{std::move(*request)}, [this, conn, &request_reader](const Message &request) {
              if (request.cls() == Class::Request) {
                return server_->process_request(conn, *request_reader, request)
                    .then([conn](std::optional<Server::Response> response) {
                      if (!response) return make_ready_future<>();

                      MessageBufferWriter response_writer{response->message.id()};
                      if (response->key) response_writer.set_key(*response->key);

                      if (!response->message.serialize(response_writer)) return make_ready_future<>();

                      temporary_buffer<char> response_buffer{response_writer.data(), response_writer.current_size()};
                      return send_response(conn, std::move(response_buffer));
                    });
              } else
                return server_->process_indication(conn, *request_reader, request).then([conn] {
                  return close(conn);
                });
            });
          });
        }).finally([this] {
      signal_task_stopped();
    });
  }
}
