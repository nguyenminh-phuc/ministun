#include <ministun/ClientSocket.h>
#include <exception>
#include <utility>
#include <seastar/net/packet-data-source.hh>
#include <ministun/Attribute.h>
#include <ministun/Header.h>
#include <ministun/Body.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  std::optional<UdpClientSocket> UdpClientSocket::make_channel(
      const socket_address &local_address, const socket_address &remote_address,
      size_t max_retries, std::chrono::milliseconds timeout) {
    try {
      UdpClientSocket socket{local_address, remote_address, max_retries, timeout};
      socket.channel_ = make_udp_channel(socket.local_address());
      socket.opened_ = true;
      return socket;
    } catch (const std::exception &e) {
      MS_ERROR("Failed to make UDP channel {}. Exception caught: {}", local_address, e.what());
      return {};
    }
  }

  future<> UdpClientSocket::close_gracefully() {
    if (!opened_) return make_ready_future<>();

    channel_.shutdown_input();
    channel_.shutdown_output();

    return repeat([this] {
      if (!receiving_) return make_ready_future<stop_iteration>(stop_iteration::yes);
      return receive_response_finished_cond_.wait().then([] { return stop_iteration::no; });
    }).then([this] {
      opened_ = false;
    });
  }

  future<std::unique_ptr<ClientSocket::Response>> UdpClientSocket::send_request(const MessageBuffer &buffer) {
    BOOST_ASSERT(opened_);

    return do_with(MessageBuffer{buffer}, size_t{}, [this](const MessageBuffer &buffer, size_t &i) {
      return with_semaphore(limit_, 1, [this, &buffer, &i] {
        response_ = nullptr;
        if (!receiving_) receive_response();

        return repeat([this, &buffer, &i] {
          if (response_) return make_ready_future<stop_iteration>(stop_iteration::yes);
          if (i == max_retries_) {
            MS_DEBUG("Maximum sending retries {} reached", max_retries_);
            return make_ready_future<stop_iteration>(stop_iteration::yes);
          }

          return send_retry(buffer, i);
        }).then([this] {
          auto nrvo{std::move(response_)};
          return nrvo;
        });
      });
    });
  }

  future<bool> UdpClientSocket::send_indication(const MessageBuffer &buffer) {
    BOOST_ASSERT(opened_);

    return with_semaphore(limit_, 1, [this, packet = net::packet{buffer.data.data(), buffer.current_size}]() mutable {
      return send_packet(std::move(packet)).then([](bool sent) {
        return sent;
      });
    });
  }

  future<bool> UdpClientSocket::send_packet(net::packet packet) {
    const auto size = packet.len();

    return channel_.send(remote_address(), std::move(packet)).then_wrapped([this, size](future<> f) {
      try {
        f.get();
        MS_DEBUG("Sent UDP packet ({} bytes) to address {}", size, remote_address());
        return true;
      } catch (const std::exception &e) {
        MS_WARN("Failed to send UDP packet ({} bytes) to address {}. Exception caught: {}",
                size, remote_address(), e.what());
        return false;
      }
    });
  }

  future<stop_iteration> UdpClientSocket::send_retry(const MessageBuffer &buffer, size_t &i) {
    return send_packet(net::packet{buffer.data.data(), buffer.current_size}).then([this, &i](bool sent) {
      if (!sent || response_) return make_ready_future<stop_iteration>(stop_iteration::yes);

      if (i != 0) MS_INFO("Waiting for message ({}ms)...", timeout_.count());
      return wait_response_cond_.wait(std::chrono::duration_cast<semaphore::duration>(timeout_))
          .handle_exception_type([](const condition_variable_timed_out &) {})
          .then([this, &i] {
            if (response_) return stop_iteration::yes;

            ++i;
            return stop_iteration::no;
          });
    });
  }

  void UdpClientSocket::receive_response() {
    receiving_ = true;
    (void) repeat([this] {
      return channel_.receive().then_wrapped([this](future<net::udp_datagram> f) {
        try {
          net::udp_datagram dgram{f.get()};

          if (dgram.get_src() != remote_address()) return stop_iteration::no;

          auto &packet = dgram.get_data();
          if (packet.len() < header_length || packet.len() > max_message_length) return stop_iteration::no;

          auto response_buffer = net::packet_data_source(std::move(packet)).get().get();
          MessageBufferReader response_reader{response_buffer};

          if (auto message = Message::parse(response_reader)) {
            Response response{
                .reader = std::move(response_reader),
                .message = std::move(*message)
            };
            response_ = std::make_unique<Response>(std::move(response));
            wait_response_cond_.signal();
            return stop_iteration::yes;
          }

          MS_DEBUG("Received incomprehensible UDP packet ({} bytes) from address {}",
                   dgram.get_data().len(), dgram.get_src());
          return stop_iteration::no;
        } catch (const std::exception &e) {
          MS_WARN("Failed to receive UDP packets. Exception caught: {}", e.what());
          return stop_iteration::yes;
        }
      });
    }).then([this] {
      receiving_ = false;
      receive_response_finished_cond_.signal();
    });
  }

  future<std::optional<TcpClientSocket>> TcpClientSocket::make_connection(
      const socket_address &local_address, const socket_address &remote_address,
      std::chrono::milliseconds timeout) {
    return do_with(
        TcpClientSocket{local_address, remote_address, timeout}, condition_variable{}, bool{},
        [timeout](TcpClientSocket &socket, condition_variable &wait_cond, bool &finished) {
          socket.socket_ = make_socket();
          socket.socket_.set_reuseaddr(true);

          (void) socket.socket_.connect(socket.remote_address(), socket.local_address())
              .then_wrapped([&socket](future<connected_socket> f) mutable {
                try {
                  socket.connected_socket_ = f.get();
                  socket.read_stream_ = socket.connected_socket_.input();
                  socket.write_stream_ = socket.connected_socket_.output();
                  socket.opened_ = true;
                  MS_DEBUG("TCP connection established {} <-> {}", socket.local_address(), socket.remote_address());
                } catch (const std::exception &e) {
                  MS_ERROR("Failed to connect to address {}. Exception caught: {}", socket.remote_address(), e.what());
                }
              }).then([&wait_cond, &finished] {
                wait_cond.signal();
                finished = true;
              });

          if (finished) return make_ready_future<std::optional<TcpClientSocket>>(std::make_optional(std::move(socket)));
          return wait_cond.wait(std::chrono::duration_cast<semaphore::duration>(timeout))
              .handle_exception_type([](const condition_variable_timed_out &) {})
              .then([&socket, &wait_cond, &finished] {
                if (!finished) socket.socket_.shutdown();
                return repeat([&wait_cond, &finished] {
                  if (finished) return make_ready_future<stop_iteration>(stop_iteration::yes);
                  return wait_cond.wait().then([] { return stop_iteration::no; });
                });
              }).then([&socket] {
                return std::make_optional(std::move(socket));
              });
        });
  }

  future<> TcpClientSocket::close_gracefully() {
    if (!opened_) return make_ready_future<>();

    connected_socket_.shutdown_input();
    connected_socket_.shutdown_output();

    return repeat([this] {
      if (!receiving_) return make_ready_future<stop_iteration>(stop_iteration::yes);
      return receive_response_finished_cond_.wait().then([] { return stop_iteration::no; });
    }).then([this] {
      opened_ = false;
    });
  }

  future<std::unique_ptr<ClientSocket::Response>> TcpClientSocket::send_request(const MessageBuffer &buffer) {
    BOOST_ASSERT(opened_);

    return with_semaphore(limit_, 1, [this, buffer = buffer] {
      return send_bytes(buffer).then([this](bool sent) {
        if (!sent) return make_ready_future<std::unique_ptr<Response>>();

        response_ = nullptr;
        if (!receiving_) receive_response();

        return wait_response_cond_.wait(std::chrono::duration_cast<semaphore::duration>(timeout_))
            .handle_exception_type([](const condition_variable_timed_out &) {})
            .then([this] {
              auto nrvo{std::move(response_)};
              return nrvo;
            });
      });
    });
  }

  future<bool> TcpClientSocket::send_indication(const MessageBuffer &buffer) {
    BOOST_ASSERT(opened_);

    return with_semaphore(limit_, 1, [this, buffer = buffer] {
      return send_bytes(buffer);
    });
  }

  future<bool> TcpClientSocket::send_bytes(const MessageBuffer &buffer) {
    const auto size = buffer.current_size;
    return write_stream_.write(buffer.data.data(), size).then([this] {
      return write_stream_.flush();
    }).then_wrapped([this, size](future<> f) {
      try {
        f.get();
        MS_DEBUG("Sent {} bytes to address {}", size, remote_address());
        return true;
      } catch (const std::exception &e) {
        MS_WARN("Failed to send {} bytes to address {}. Exception caught: {}", remote_address(), size, e.what());
        return false;
      }
    });
  }

  future<std::optional<temporary_buffer<char>>> TcpClientSocket::receive_bytes(size_t size) {
    return read_stream_.read_exactly(size).then_wrapped([this, size](future<temporary_buffer<char>> f) {
      try {
        temporary_buffer<char> buffer{f.get()};

        if (buffer.size() < size) {
          MS_DEBUG("Expected {} bytes, received {} bytes from address {}", size, buffer.size(), remote_address());
          return std::optional<temporary_buffer<char>>{};
        }

        return std::make_optional(std::move(buffer));
      } catch (const std::exception &e) {
        MS_WARN("Failed to receive bytes from address {}. Exception caught: {}", remote_address(), e.what());
        return std::optional<temporary_buffer<char>>{};
      }
    });
  }

  void TcpClientSocket::receive_response() {
    receiving_ = true;
    (void) receive_bytes(header_length).then([this](std::optional<temporary_buffer<char>> header_buffer) {
      if (!header_buffer) return make_ready_future<>();

      MessageBufferReader header_reader{*header_buffer};
      MS_GET(pair, Header::parse(header_reader), make_ready_future<>())
      const auto header = pair->first;
      const auto body_length = pair->second;

      if (!body_length) {
        Response response{
            .reader = std::move(header_reader),
            .message = Message{header}
        };
        response_ = std::make_unique<Response>(std::move(response));
        return make_ready_future<>();
      }

      return receive_bytes(body_length).then([this, header_buffer = std::move(*header_buffer), header, body_length]
                                                 (std::optional<temporary_buffer<char>> body_buffer) mutable {
        if (!body_buffer) return;

        MessageBufferReader body_reader{header_buffer, header.id(), *body_buffer};
        MS_GET0(body, Body::parse(body_reader, body_length))

        Response response{
            .reader = std::move(body_reader),
            .message = Message{header, std::move(*body)}
        };
        response_ = std::make_unique<Response>(std::move(response));
      });
    }).then([this] {
      receiving_ = false;
      wait_response_cond_.signal();
      receive_response_finished_cond_.signal();
    });
  }
}
