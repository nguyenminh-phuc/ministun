#include <ministun/MiniStun.h>

using namespace seastar;
using namespace ms;

static constexpr unsigned char reqltc[] =
    "\x00\x01\x00\x60"
    "\x21\x12\xa4\x42"
    "\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"
    "\x00\x06\x00\x12"
    "\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83"
    "\xe3\x82\xaf\xe3\x82\xb9\x00\x00"
    "\x00\x15\x00\x1c"
    "\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36"
    "\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79"
    "\x36\x34\x73\x41"
    "\x00\x14\x00\x0b"
    "\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00"
    "\x00\x08\x00\x14"
    "\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71"
    "\x2e\x85\xc9\xa2\x8c\xa8\x96\x66";

static constexpr Id id = {
    '\x78', '\xad', '\x34', '\x33',
    '\xc6', '\xad', '\x72', '\xc0',
    '\x29', '\xda', '\x41', '\x2e'
};
static const sstring username = "\u30de\u30c8\u30ea\u30c3\u30af\u30b9";
static const sstring password = "TheMatrIX";
static const sstring nonce = "f//499k954d6OL34oL9FSTvy64sA";
static const sstring realm = "example.org";
static const ipv6_addr respv6_mapped_address{"2001:db8:1234:5678:11:2233:4455:6677", 32853};

static void parse_test() {
  temporary_buffer<char> request_buffer{reinterpret_cast<const char *>(reqltc), sizeof reqltc - 1};
  MessageBufferReader request_reader{request_buffer};

  const auto request = Message::parse(request_reader);
  if (!request) throw std::runtime_error("Failed to parse");

  const auto integrity = request->find<MessageIntegrityAttribute>();
  if (!integrity) throw std::runtime_error("Failed to find MESSAGE-INTEGRITY");

  const auto key = LongTermAuthenticator::make_key(
      username,
      realm,
      std::vector<char>{password.cbegin(), password.cend()});
  if (!integrity->validate(request_reader, key)) throw std::runtime_error("Failed to validate MESSAGE-INTEGRITY");
}

static void serialize_test() {
  Message message{Header{Method::Binding, Class::Request, id}};
  message.add(make_shared<UsernameAttribute>(username));
  message.add(make_shared<NonceAttribute>(nonce));
  message.add(make_shared<RealmAttribute>(realm));
  message.add(MessageIntegrityAttribute::dummy());

  const auto key = LongTermAuthenticator::make_key(
      username,
      realm,
      std::vector<char>{password.cbegin(), password.cend()});

  MessageBufferWriter writer{id};
  writer.set_key(key);
  if (!message.serialize(writer)) throw std::runtime_error("Failed to serialize");

  const std::vector<char> buffer{writer.data(), writer.data() + writer.current_size()};
  const std::vector<char> expected_buffer{reqltc, reqltc + sizeof reqltc - 1};
  if (buffer != expected_buffer) throw std::exception();
}

static future<> authen_test() {
  std::map<sstring, std::vector<char>> users{
      {username, std::vector<char>{password.cbegin(), password.cend()}}
  };

  auto authenticator = seastar::make_shared<StaticLongTermAuthenticator>(
      std::move(users),
      std::vector<char>{'\0'},
      realm,
      SecurityFeatureSet{.password_algorithms = false, .username_anonymity = false},
      LongTermAuthenticator::default_nonce_timeout,
      true);

  return do_with(
      shared_ptr<Authenticator>{std::move(authenticator)},
      temporary_buffer<char>{reinterpret_cast<const char *>(reqltc), sizeof reqltc - 1},
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
    parse_test();
    serialize_test();

    return authen_test();
  });
}
