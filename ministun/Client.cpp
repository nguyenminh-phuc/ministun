#include <ministun/Client.h>
#include <memory>
#include <ministun/Attribute.h>
#include <ministun/Buffer.h>
#include <ministun/ClientCred.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  future<std::optional<BindingResult>> Client::test_binding() {
    return with_semaphore(limit_, 1, [this] {
      return do_with(Message{Header{Method::Binding, Class::Request}}, [this](Message &request) {
        return send_retry(request).then([this](std::optional<Message> response) -> std::optional<BindingResult> {
          if (!response) {
            MS_WARN("No response message");
            return std::optional<BindingResult>{};
          }

          std::optional<socket_address> address;
          if (auto xor_mapped_address = response->find<XorMappedAddressAttribute>())
            address = xor_mapped_address->address();
          else if (auto mapped_address = response->find<MappedAddressAttribute>())
            address = mapped_address->address();

          if (!address) {
            MS_WARN("No mapped address is present in message");
            return std::optional<BindingResult>{};
          }

          return BindingResult{
              .local_address = config_.socket->local_address(),
              .mapped_address = *address
          };
        });
      });
    });
  }

  future<std::optional<Message>> Client::send_retry(const Message &request) const {
    return do_with(
        std::optional<Message>{},
        [this, &request](std::optional<Message> &result) {
          return repeat([this, &request, &result] {
            return do_with(
                MessageBufferWriter{request.id()}, Message{request},
                [this, &result](MessageBufferWriter &request_writer, Message &request) {
                  if (config_.credential) config_.credential->apply_auth(request_writer, request);

                  BOOST_VERIFY(request.serialize(request_writer));
                  return config_.socket->send_request(request_writer.buffer())
                      .then([this, &result](std::unique_ptr<ClientSocket::Response> response) {
                        if (!response) return stop_iteration::yes;

                        if (!config_.credential) {
                          result = std::move(response->message);
                          return stop_iteration::yes;
                        }

                        const auto auth_result = config_.credential->validate_auth(response->reader, response->message);
                        switch (auth_result) {
                          case ClientCred::Result::Success:
                            result = std::move(response->message);
                            return stop_iteration::yes;
                          case ClientCred::Result::Error:
                            return stop_iteration::yes;
                          case ClientCred::Result::Retry:
                            return stop_iteration::no;
                        }
                      });
                });
          }).then([&result] {
            auto nrvo{std::move(result)};
            return nrvo;
          });
        });
  }

  future<> Client::close_gracefully() const {
    return config_.socket->close_gracefully();
  }
}
