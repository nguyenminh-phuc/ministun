#include <ministun/MiniStun.h>

using namespace seastar;
using namespace ms;

// https://www.rfc-editor.org/errata/rfc8489
static constexpr char reqltc[] = {
    '\x00', '\x01', '\x00', '\x90', //     Request type and message length
    '\x21', '\x12', '\xa4', '\x42', //     Magic cookie
    '\x78', '\xad', '\x34', '\x33', //  }
    '\xc6', '\xad', '\x72', '\xc0', //  }  Transaction ID
    '\x29', '\xda', '\x41', '\x2e', //  }
    '\x00', '\x1e', '\x00', '\x20', //     USERHASH attribute header
    '\x4a', '\x3c', '\xf3', '\x8f', //  }
    '\xef', '\x69', '\x92', '\xbd', //  }
    '\xa9', '\x52', '\xc6', '\x78', //  }
    '\x04', '\x17', '\xda', '\x0f', //  }  Userhash value (32  bytes)
    '\x24', '\x81', '\x94', '\x15', //  }
    '\x56', '\x9e', '\x60', '\xb2', //  }
    '\x05', '\xc4', '\x6e', '\x41', //  }
    '\x40', '\x7f', '\x17', '\x04', //  }
    '\x00', '\x15', '\x00', '\x29', //     NONCE attribute header
    '\x6f', '\x62', '\x4d', '\x61', //  }
    '\x74', '\x4a', '\x6f', '\x73', //  }
    '\x32', '\x41', '\x41', '\x41', //  }
    '\x43', '\x66', '\x2f', '\x2f', //  }
    '\x34', '\x39', '\x39', '\x6b', //  }  Nonce value and padding (3 bytes)
    '\x39', '\x35', '\x34', '\x64', //  }
    '\x36', '\x4f', '\x4c', '\x33', //  }
    '\x34', '\x6f', '\x4c', '\x39', //  }
    '\x46', '\x53', '\x54', '\x76', //  }
    '\x79', '\x36', '\x34', '\x73', //  }
    '\x41', '\x00', '\x00', '\x00', //  }
    '\x00', '\x14', '\x00', '\x0b', //     REALM attribute header
    '\x65', '\x78', '\x61', '\x6d', //  }
    '\x70', '\x6c', '\x65', '\x2e', //  }  Realm value (11  bytes) and padding (1 byte)
    '\x6f', '\x72', '\x67', '\x00', //  }
    '\x00', '\x1d', '\x00', '\x04', //     PASSWORD-ALGORITHM attribute header
    '\x00', '\x02', '\x00', '\x00', //     PASSWORD-ALGORITHM value (4 bytes)
    '\x00', '\x1c', '\x00', '\x20', //     MESSAGE-INTEGRITY-SHA256 attribute header
    '\xb5', '\xc7', '\xbf', '\x00', //  }
    '\x5b', '\x6c', '\x52', '\xa2', //  }
    '\x1c', '\x51', '\xc5', '\xe8', //  }
    '\x92', '\xf8', '\x19', '\x24', //  }  HMAC-SHA256 value
    '\x13', '\x62', '\x96', '\xcb', //  }
    '\x92', '\x7c', '\x43', '\x14', //  }
    '\x93', '\x09', '\x27', '\x8c', //  }
    '\xc6', '\x51', '\x8e', '\x65'  //  }
};

static constexpr Id id = {
    '\x78', '\xad', '\x34', '\x33',
    '\xc6', '\xad', '\x72', '\xc0',
    '\x29', '\xda', '\x41', '\x2e'
};
static const sstring username = "\u30de\u30c8\u30ea\u30c3\u30af\u30b9";
static const sstring password = "TheMatrIX";
static const sstring nonce = "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA";
static const sstring realm = "example.org";
static const ipv6_addr respv6_mapped_address{"2001:db8:1234:5678:11:2233:4455:6677", 32853};

static void parse_test() {
  temporary_buffer<char> request_buffer{reqltc, sizeof reqltc};
  MessageBufferReader request_reader{request_buffer};

  const auto request = Message::parse(request_reader);
  if (!request) throw std::runtime_error("Failed to parse");

  const auto integrity_sha256 = request->find<MessageIntegritySha256Attribute>();
  if (!integrity_sha256) throw std::runtime_error("Failed to find MESSAGE-INTEGRITY-SHA256");

  const auto key = LongTermAuthenticator::make_key(
      username,
      realm,
      std::vector<char>{password.cbegin(), password.cend()},
      PasswordAlgorithm::Sha256);
  if (!integrity_sha256->validate(request_reader, key))
    throw std::runtime_error("Failed to validate MESSAGE-INTEGRITY-SHA256");
}

static void serialize_test() {
  Message message{Header{Method::Binding, Class::Request, id}};
  message.add(make_shared<UserhashAttribute>(username, realm));
  message.add(make_shared<NonceAttribute>(nonce));
  message.add(make_shared<RealmAttribute>(realm));
  message.add(seastar::make_shared<PasswordAlgorithmAttribute>(PasswordAlgorithm::Sha256, std::vector<char>{}));
  message.add(MessageIntegritySha256Attribute::dummy());

  const auto key = LongTermAuthenticator::make_key(
      username,
      realm,
      std::vector<char>{password.cbegin(), password.cend()},
      PasswordAlgorithm::Sha256);

  MessageBufferWriter writer{id};
  writer.set_key(key);
  if (!message.serialize(writer)) throw std::runtime_error("Failed to serialize");

  const std::vector<char> buffer{writer.data(), writer.data() + writer.current_size()};
  const std::vector<char> expected_buffer{reqltc, reqltc + sizeof reqltc};
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
      SecurityFeatureSet{.password_algorithms = true, .username_anonymity = true},
      LongTermAuthenticator::default_nonce_timeout,
      true);

  return do_with(
      shared_ptr<Authenticator>{std::move(authenticator)},
      temporary_buffer<char>{reinterpret_cast<const char *>(reqltc), sizeof reqltc},
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
