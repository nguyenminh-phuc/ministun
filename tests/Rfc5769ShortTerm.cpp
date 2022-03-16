#include <ministun/MiniStun.h>

using namespace seastar;
using namespace ms;

// Request message
static constexpr unsigned char req[] =
    "\x00\x01\x00\x58"
    "\x21\x12\xa4\x42"
    "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
    "\x80\x22\x00\x10"
    "STUN test client"
    "\x00\x24\x00\x04"
    "\x6e\x00\x01\xff"
    "\x80\x29\x00\x08"
    "\x93\x2f\xf9\xb1\x51\x26\x3b\x36"
    "\x00\x06\x00\x09"
    "\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20"
    "\x00\x08\x00\x14"
    "\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5"
    "\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2"
    "\x80\x28\x00\x04"
    "\xe5\x7a\x3b\xcf";

// In rfc5769, the paddings can be of arbitrary values, I change them to '\x00' to conform with the new spec rfc8489
static constexpr unsigned char new_req[] =
    "\x00\x01\x00\x58"
    "\x21\x12\xa4\x42"
    "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
    "\x80\x22\x00\x10"
    "STUN test client"
    "\x00\x24\x00\x04"
    "\x6e\x00\x01\xff"
    "\x80\x29\x00\x08"
    "\x93\x2f\xf9\xb1\x51\x26\x3b\x36"
    "\x00\x06\x00\x09"
    "\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x00\x00\x00"
    "\x00\x08\x00\x14"
    "\x79\x07\xc2\xd2\xed\xbf\xea\x48\x0e\x4c\x76\xd8"
    "\x29\x62\xd5\xc3\x74\x2a\xf9\xe3"
    "\x80\x28\x00\x04"
    "\xe3\x52\x92\x8d";

static constexpr Id id = {
    '\xb7', '\xe7', '\xa7', '\x01',
    '\xbc', '\x34', '\xd6', '\x86',
    '\xfa', '\x87', '\xdf', '\xae'
};
static const sstring req_software = "STUN test client";
static const sstring req_username = "evtj:h6vY";
static const sstring req_password = "VOkJxbRl1RmTxUk/WvJxBt";

// IPv4 response message
static constexpr unsigned char respv4[] =
    "\x01\x01\x00\x3c"
    "\x21\x12\xa4\x42"
    "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
    "\x80\x22\x00\x0b"
    "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20"
    "\x00\x20\x00\x08"
    "\x00\x01\xa1\x47\xe1\x12\xa6\x43"
    "\x00\x08\x00\x14"
    "\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9"
    "\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7"
    "\x80\x28\x00\x04"
    "\xc0\x7d\x4c\x96";

static constexpr unsigned char new_respv4[] =
    "\x01\x01\x00\x3c"
    "\x21\x12\xa4\x42"
    "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
    "\x80\x22\x00\x0b"
    "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x00"
    "\x00\x20\x00\x08"
    "\x00\x01\xa1\x47\xe1\x12\xa6\x43"
    "\x00\x08\x00\x14"
    "\x5d\x6b\x58\xbe\xad\x94\xe0\x7e\xef\x0d\xfc\x12"
    "\x82\xa2\xbd\x08\x43\x14\x10\x28"
    "\x80\x28\x00\x04"
    "\x25\x16\x7a\x15";

static const sstring resp_software = "test vector";
static const socket_address respv4_mapped_address{ipv4_addr{"192.0.2.1", 32853}};

// IPv6 response message
static constexpr unsigned char respv6[] =
    "\x01\x01\x00\x48"
    "\x21\x12\xa4\x42"
    "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
    "\x80\x22\x00\x0b"
    "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20"
    "\x00\x20\x00\x14"
    "\x00\x02\xa1\x47"
    "\x01\x13\xa9\xfa\xa5\xd3\xf1\x79"
    "\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9"
    "\x00\x08\x00\x14"
    "\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c"
    "\x82\x92\xc2\x75\xbf\xe3\xed\x41"
    "\x80\x28\x00\x04"
    "\xc8\xfb\x0b\x4c";

static constexpr unsigned char new_respv6[] =
    "\x01\x01\x00\x48"
    "\x21\x12\xa4\x42"
    "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
    "\x80\x22\x00\x0b"
    "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x00"
    "\x00\x20\x00\x14"
    "\x00\x02\xa1\x47"
    "\x01\x13\xa9\xfa\xa5\xd3\xf1\x79"
    "\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9"
    "\x00\x08\x00\x14"
    "\xbd\x03\x6d\x6a\x33\x17\x50\xdf\xe2\xed\xc5\x8e"
    "\x64\x34\x55\xcf\xf5\xc8\xe2\x64"
    "\x80\x28\x00\x04"
    "\x4f\x26\x02\x93";

static const socket_address respv6_mapped_address{ipv6_addr{"2001:db8:1234:5678:11:2233:4455:6677", 32853}};

static void parse_req_test() {
  temporary_buffer<char> request_buffer{reinterpret_cast<const char *>(req), sizeof req - 1};
  MessageBufferReader request_reader{request_buffer};

  const auto request = Message::parse(request_reader);
  if (!request) throw std::runtime_error("Failed to parse");

  const auto integrity = request->find<MessageIntegrityAttribute>();
  if (!integrity) throw std::runtime_error("Failed to find MESSAGE-INTEGRITY");

  const auto key = ShortTermAuthenticator::make_key(std::vector<char>{req_password.cbegin(), req_password.cend()});
  if (!integrity->validate(request_reader, key)) throw std::runtime_error("Failed to validate MESSAGE-INTEGRITY");
}

static void parse_resp_test(const char *buffer, size_t size, const socket_address& expected_mapped_address) {
  temporary_buffer<char> response_buffer{buffer, size};
  MessageBufferReader response_reader{response_buffer};

  const auto response = Message::parse(response_reader);
  if (!response) throw std::runtime_error("Failed to parse");

  const auto integrity = response->find<MessageIntegrityAttribute>();
  if (!integrity) throw std::runtime_error("Failed to find MESSAGE-INTEGRITY");

  const auto key = ShortTermAuthenticator::make_key(std::vector<char>{req_password.cbegin(), req_password.cend()});
  if (!integrity->validate(response_reader, key)) throw std::runtime_error("Failed to validate MESSAGE-INTEGRITY");

  const auto mapped_address = response->find<XorMappedAddressAttribute>();
  if (!mapped_address) throw std::runtime_error("Failed to find XOR-MAPPED-ADDRESS");
  if (mapped_address->address() != expected_mapped_address) throw std::exception();
}

static void serialize_req_test() {
  Message message{Header{Method::Binding, Class::Request, id}};
  message.add(make_shared<SoftwareAttribute>(req_software));
  message.add(seastar::make_shared<IncomprehensibleAttribute>(
      static_cast<AttributeType>(0x0024),
      std::vector<char>{'\x6e', '\x00', '\x01', '\xff'}));
  message.add(seastar::make_shared<IncomprehensibleAttribute>(
      static_cast<AttributeType>(0x8029),
      std::vector<char>{'\x93', '\x2f', '\xf9', '\xb1', '\x51', '\x26', '\x3b', '\x36'}));
  message.add(make_shared<UsernameAttribute>(req_username));
  message.add(MessageIntegrityAttribute::dummy());
  message.add(make_shared<FingerprintAttribute>());

  MessageBufferWriter writer{id};
  writer.set_key(std::vector<char>{req_password.cbegin(), req_password.cend()});
  if (!message.serialize(writer)) throw std::runtime_error("Failed to serialize");

  const std::vector<char> buffer{writer.data(), writer.data() + writer.current_size()};
  const std::vector<char> expected_buffer{new_req, new_req + sizeof new_req - 1};
  if (buffer != expected_buffer) throw std::exception();
}

static void serialize_resp_test(
    const socket_address& mapped_address,
    const char *expected_buffer, size_t expected_size) {
  Message message{Header{Method::Binding, Class::SuccessResponse, id}};
  message.add(make_shared<SoftwareAttribute>(resp_software));
  message.add(make_shared<XorMappedAddressAttribute>(mapped_address));
  message.add(MessageIntegrityAttribute::dummy());
  message.add(make_shared<FingerprintAttribute>());

  MessageBufferWriter writer{id};
  writer.set_key(std::vector<char>{req_password.cbegin(), req_password.cend()});
  if (!message.serialize(writer)) throw std::runtime_error("Failed to serialize");

  const std::vector<char> buffer{writer.data(), writer.data() + writer.current_size()};
  if (buffer != std::vector<char>{expected_buffer, expected_buffer + expected_size}) throw std::exception();
}

static future<> authen_test() {
  std::map<sstring, std::vector<char>> users{
      {req_username, std::vector<char>{req_password.cbegin(), req_password.cend()}}
  };

  return do_with(
      shared_ptr<Authenticator>{seastar::make_shared<StaticShortTermAuthenticator>(std::move(users))},
      temporary_buffer<char>{reinterpret_cast<const char *>(req), sizeof req - 1},
      [](shared_ptr<Authenticator> &auth, temporary_buffer<char> &request_buffer) {
        return do_with(MessageBufferReader{request_buffer}, [&auth](MessageBufferReader &request_reader) {
          auto request = Message::parse(request_reader);
          if (!request) throw std::runtime_error("Failed to parse");

          return do_with(Message{std::move(*request)}, [&auth, &request_reader](Message &request) {
            return do_with(AuthInput{respv6_mapped_address, request_reader, request}, [&auth](AuthInput &input) {
              return auth->check(input).then([](const shared_ptr<AuthResult> &result) {
                if (result->type() != AuthResult::Type::Success) throw std::runtime_error("Failed to authenticate");
              });
            });
          });
        });
      });
}

int main(int ac, char **av) {
  app_template app;
  return app.run(ac, av, [&] {
    parse_req_test();
    parse_resp_test(reinterpret_cast<const char *>(respv4), sizeof respv4 - 1, respv4_mapped_address);
    parse_resp_test(reinterpret_cast<const char *>(respv6), sizeof respv6 - 1, respv6_mapped_address);

    serialize_req_test();
    serialize_resp_test(respv4_mapped_address, reinterpret_cast<const char *>(new_respv4), sizeof new_respv4 - 1);
    serialize_resp_test(respv6_mapped_address, reinterpret_cast<const char *>(new_respv6), sizeof new_respv6 - 1);

    return authen_test();
  });
}
