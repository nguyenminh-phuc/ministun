#include <ministun/Attribute.h>
#include <stdint.h>
#include <string.h>
#include <map>
#include <openssl/hmac.h> // https://www.openssl.org/docs/man1.1.1/man3/HMAC.html
#include <boost/crc.hpp>
#include <openssl/sha.h>
#include <seastar/net/ip.hh>
#include <ministun/Authenticator.h>

using namespace seastar;

namespace ms {
  static constexpr std::array<char, 3> padding_bytes{};

  class HashContext final {
  public:
    HashContext() : context_{} {
    }

    ~HashContext() {
      if (context_) HMAC_CTX_free(context_);
    }

    template<class T>
    bool validate(const T &integrity, const MessageBufferReader &reader, const std::vector<char> &key) {
      static_assert(std::is_same<T, MessageIntegrityAttribute>::value ||
                    std::is_same<T, MessageIntegritySha256Attribute>::value);

      const EVP_MD *func;
      std::optional<size_t> message_integrity_pos;
      static constexpr auto message_integrity_length = T::dummy_hash.size();
      if constexpr (std::is_same<T, MessageIntegrityAttribute>::value) {
        func = EVP_sha1();
        message_integrity_pos = reader.message_integrity_pos();
      } else {
        func = EVP_sha256();
        message_integrity_pos = reader.message_integrity_sha256_pos();
      }

      if (!message_integrity_pos || key.empty()) return false;

      if (context_) HMAC_CTX_free(context_);
      context_ = HMAC_CTX_new();
      BOOST_ASSERT(context_);

      BOOST_VERIFY(HMAC_Init_ex(context_, key.data(), static_cast<int>(key.size()), func, nullptr));

      // Type
      if (reader.header_buffer())
        BOOST_VERIFY(HMAC_Update(
            context_,
            reinterpret_cast<const unsigned char *>(reader.header_buffer()->get()), sizeof(uint16_t)));
      else
        BOOST_VERIFY(HMAC_Update(context_, reinterpret_cast<const unsigned char *>(reader.data()), sizeof(uint16_t)));

      // Length
      uint16_t length;
      if (reader.header_buffer()) length = *message_integrity_pos + sizeof(uint32_t) + message_integrity_length;
      else length = -header_length + *message_integrity_pos + sizeof(uint32_t) + message_integrity_length;
      length = net::hton(length);
      BOOST_VERIFY(HMAC_Update(context_, reinterpret_cast<const unsigned char *>(&length), sizeof(uint16_t)));

      // Everything up to the integrity attribute
      if (reader.header_buffer()) {
        BOOST_VERIFY(HMAC_Update(
            context_,
            reinterpret_cast<const unsigned char *>(reader.header_buffer()->get() + sizeof(uint32_t)),
            header_length - sizeof(uint32_t)));
        BOOST_VERIFY(HMAC_Update(
            context_,
            reinterpret_cast<const unsigned char *>(reader.data()), *message_integrity_pos - sizeof(uint32_t)));
      } else {
        BOOST_VERIFY(HMAC_Update(
            context_,
            reinterpret_cast<const unsigned char *>(reader.data() + sizeof(uint32_t)),
            *message_integrity_pos - sizeof(uint32_t)));
      }

      std::array<char, message_integrity_length> hash{};
      unsigned hash_length;
      BOOST_VERIFY(HMAC_Final(context_, reinterpret_cast<unsigned char *>(hash.data()), &hash_length));
      BOOST_ASSERT(hash_length == message_integrity_length);

      return hash == integrity.string();
    }

  private:
    HMAC_CTX *context_;
  };

  static shared_ptr<ErrorCodeAttribute> make_error(ErrorCode code) {
    if (auto reason_phrase = ErrorCodeAttribute::get_reason_phrase(code))
      return ::make_shared<ErrorCodeAttribute>(code, *reason_phrase);
    return make_shared<ErrorCodeAttribute>(code);
  }

  static char serialize_family(Family family) {
    return family == Family::Inet ? 0x01 : 0x02;
  }

  template<class T>
  static bool serialize_message_integrity(MessageBufferWriter &writer) {
    static_assert(std::is_same<T, MessageIntegrityAttribute>::value ||
                  std::is_same<T, MessageIntegritySha256Attribute>::value);

    static constexpr auto message_integrity_length = T::dummy_hash.size();

    MS_GETREF(key, writer.key(), false)

    writer.replace<uint16_t>(writer.current_size() - sizeof(uint16_t), message_integrity_length);
    writer.write_raw(T::dummy_hash.data(), message_integrity_length);

    writer.replace_body_length();

    auto data_ptr = reinterpret_cast<const unsigned char *>(writer.data());
    auto data_size = writer.current_size() - sizeof(uint32_t) - message_integrity_length;
    auto hash_ptr = reinterpret_cast<unsigned char *>(writer.data()) + data_size + sizeof(uint32_t);

    unsigned length;
    const auto func = std::is_same<T, MessageIntegrityAttribute>::value ? EVP_sha1() : EVP_sha256();
    BOOST_VERIFY(HMAC(func, key->data(), static_cast<int>(key->size()), data_ptr, data_size, hash_ptr, &length));
    BOOST_ASSERT(length == message_integrity_length);

    return true;
  }

  static std::optional<Family> parse_family(char value) {
    if (value == 0x01) return Family::Inet;
    else if (value == 0x02) return Family::Inet6;
    return {};
  }

  shared_ptr<Attribute> Attribute::parse(MessageBufferReader &reader) {
    MS_GET(type_short, reader.read<uint16_t>(), nullptr)
    const auto type = static_cast<AttributeType>(*type_short);

    MS_GET(length, reader.read<uint16_t>(), nullptr)
    if (*length > max_attribute_value_length) return {};

    const auto value_pos = reader.pos();

    shared_ptr<Attribute> attribute;
    switch (type) {
      case AttributeType::MappedAddress: {
        MS_GET(mapped_address, MappedAddressAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*mapped_address));
        break;
      }
      case AttributeType::Realm:
      case AttributeType::Nonce: {
        MS_GET(string, EscapedStringAttribute::parse_value(reader, *length, type), nullptr)
        attribute = string;
        break;
      }
      case AttributeType::Username:
      case AttributeType::AlternateDomain:
      case AttributeType::Software: {
        MS_GET(string, ArbitraryStringAttribute::parse_value(reader, *length, type), nullptr)
        attribute = string;
        break;
      }
      case AttributeType::MessageIntegrity: {
        MS_GET(message_integrity,
               FixedStringAttribute<20>::parse_value<MessageIntegrityAttribute>(reader, *length), nullptr)
        attribute = message_integrity;
        break;
      }
      case AttributeType::ErrorCode: {
        MS_GET(error_code, ErrorCodeAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*error_code));
        break;
      }
      case AttributeType::UnknownAttributes: {
        MS_GET(unknown_attributes, UnknownAttributesAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*unknown_attributes));
        break;
      }
      case AttributeType::MessageIntegritySha256: {
        MS_GET(message_integrity_sha256,
               FixedStringAttribute<32>::parse_value<MessageIntegritySha256Attribute>(reader, *length), nullptr)
        attribute = message_integrity_sha256;
        break;
      }
      case AttributeType::PasswordAlgorithm: {
        MS_GET(password_algorithm, PasswordAlgorithmAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*password_algorithm));
        break;
      }
      case AttributeType::Userhash: {
        MS_GET(userhash, FixedStringAttribute<32>::parse_value<UserhashAttribute>(reader, *length), nullptr)
        attribute = userhash;
        break;
      }
      case AttributeType::XorMappedAddress: {
        MS_GET(xor_mapped_address, XorMappedAddressAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*xor_mapped_address));
        break;
      }
      case AttributeType::PasswordAlgorithms: {
        MS_GET(password_algorithms, PasswordAlgorithmsAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*password_algorithms));
        break;
      }
      case AttributeType::AlternateServer: {
        MS_GET(alternate_server, AlternateServerAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*alternate_server));
        break;
      }
      case AttributeType::Fingerprint: {
        MS_GET(fingerprint, FingerprintAttribute::parse_value(reader, *length), nullptr)
        attribute = make_shared(std::move(*fingerprint));
        break;
      }
      default: {
        MS_DEBUG("Incomprehensible Attribute {:#X}", type);
        MS_GET(body, reader.read_raw(*length), nullptr)
        attribute = ::make_shared<IncomprehensibleAttribute>(type, std::vector<char>{body, body + *length});
      }
    }

    if (reader.pos() - value_pos != *length) return {};

    const auto padding = *length % 4 ? (4 - (*length % 4)) : 0;
    if (padding) reader.skip(padding);

    return attribute;
  }

  bool Attribute::serialize(MessageBufferWriter &writer) {
    writer.write<uint16_t>(Utils::to_underlying(type_));

    const auto length_pos = writer.current_size();
    writer.write<uint16_t>(0);

    const auto value_pos = writer.current_size();
    if (!serialize_value(writer)) return false;

    const auto length = writer.current_size() - value_pos;
    const auto padding = length % 4 ? (4 - (length % 4)) : 0;

    if (length + padding > max_attribute_value_length) return false;
    writer.replace<uint16_t>(length_pos, length);

    if (padding) writer.write_raw(padding_bytes.data(), padding);

    return true;
  }

  shared_ptr<ArbitraryStringAttribute>
  ArbitraryStringAttribute::parse_value(BufferReader &reader, size_t length, AttributeType type) {
    MS_GET(data, reader.read_raw(length), nullptr)

    sstring string{data, data + length};
    if (strlen(string.c_str()) != string.size()) return {}; // not a null-terminated string

    switch (type) {
      case AttributeType::Username:
        if (length > max_username_length) return {};
        return make_shared<UsernameAttribute>(std::move(string));
      case AttributeType::AlternateDomain:
        if (length > max_alternate_domain_length) return {};
        return make_shared<AlternateDomainAttribute>(std::move(string));
      case AttributeType::Software:
        if (length > max_software_length) return {};
        return make_shared<SoftwareAttribute>(std::move(string));
      default:
        return {};
    }
  }

  bool ArbitraryStringAttribute::serialize_value(MessageBufferWriter &writer) const {
    writer.write_raw(string_.data(), string_.size());
    return true;
  }

  shared_ptr<EscapedStringAttribute>
  EscapedStringAttribute::parse_value(BufferReader &reader, size_t length, AttributeType type) {
    MS_GET(data, reader.read_raw(length), nullptr)

    sstring string{data, data + length};
    if (strlen(string.c_str()) != string.size()) return {};

    // TODO: check whether the characters are escaped properly

    switch (type) {
      case AttributeType::Realm:
        if (length > max_realm_length) return {};
        return make_shared<RealmAttribute>(std::move(string));
      case AttributeType::Nonce:
        if (length > max_nonce_length) return {};
        return make_shared<NonceAttribute>(std::move(string));
      default:
        return {};
    }
  }

  std::optional<MappedAddressAttribute>
  MappedAddressAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    [[maybe_unused]] MS_GET(empty, reader.read<uint8_t>(), std::nullopt)

    MS_GET(raw_family, reader.read<uint8_t>(), std::nullopt)
    MS_GET(family, parse_family(*raw_family), std::nullopt)
    if (*family == Family::Inet && length != 8) return {};
    if (*family == Family::Inet6 && length != 20) return {};

    MS_GET(port, reader.read<uint16_t>(), std::nullopt)

    net::inet_address address;
    if (*family == Family::Inet) {
      MS_GET(raw_ipv4, reader.read_raw(sizeof(net::ipv4_address)), std::nullopt)
      address = net::ipv4_address::read(raw_ipv4);
    } else {
      MS_GET(raw_ipv6, reader.read_raw(sizeof(net::ipv6_address)), std::nullopt)
      address = net::ipv6_address::read(raw_ipv6);
    }

    return MappedAddressAttribute{socket_address{address, *port}};
  }

  bool MappedAddressAttribute::serialize_value(MessageBufferWriter &writer) const {
    const auto family = static_cast<Family>(address_.family());

    writer.write<uint8_t>(0);
    writer.write<uint8_t>(serialize_family(family));
    writer.write<uint16_t>(address_.port());
    if (family == Family::Inet) {
      std::array<char, 4> raw_ipv4{};
      address_.addr().as_ipv4_address().write(raw_ipv4.data());
      writer.write_raw(raw_ipv4.data(), 4);
    } else {
      std::array<char, 16> raw_ipv6{};
      address_.addr().as_ipv6_address().write(raw_ipv6.data());
      writer.write_raw(raw_ipv6.data(), 16);
    }

    return true;
  }

  std::optional<XorMappedAddressAttribute>
  XorMappedAddressAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    [[maybe_unused]] MS_GET(empty, reader.read<uint8_t>(), std::nullopt)

    MS_GET(raw_family, reader.read<uint8_t>(), std::nullopt)
    MS_GET(family, parse_family(*raw_family), std::nullopt)
    if (*family == Family::Inet && length != 8) return {};
    if (*family == Family::Inet6 && length != 20) return {};

    MS_GET(raw_xport, reader.read_raw(sizeof(uint16_t)), std::nullopt)
    std::array<uint8_t, 2> raw_port{};
    raw_port[0] = raw_xport[0] ^ 0x21;
    raw_port[1] = raw_xport[1] ^ 0x12;
    const uint16_t port = (static_cast<uint16_t>(raw_port[0]) << 8) | raw_port[1];

    net::inet_address address;
    if (*family == Family::Inet) {
      MS_GET(raw_xipv4, reader.read_raw(sizeof(net::ipv4_address)), std::nullopt)
      std::array<uint8_t, 4> raw_ipv4{};
      raw_ipv4[0] = raw_xipv4[0] ^ 0x21;
      raw_ipv4[1] = raw_xipv4[1] ^ 0x12;
      raw_ipv4[2] = raw_xipv4[2] ^ 0xA4;
      raw_ipv4[3] = raw_xipv4[3] ^ 0x42;
      address = net::ipv4_address::read(reinterpret_cast<const char *>(raw_ipv4.data()));
    } else {
      MS_GET(raw_xipv6, reader.read_raw(sizeof(net::ipv6_address)), std::nullopt)
      std::array<uint8_t, 16> raw_ipv6{};
      raw_ipv6[0] = raw_xipv6[0] ^ 0x21;
      raw_ipv6[1] = raw_xipv6[1] ^ 0x12;
      raw_ipv6[2] = raw_xipv6[2] ^ 0xA4;
      raw_ipv6[3] = raw_xipv6[3] ^ 0x42;
      for (auto i = 4; i < 16; ++i) raw_ipv6[i] = raw_xipv6[i] ^ (reader.id())[i - 4];
      address = net::ipv6_address::read(reinterpret_cast<const char *>(raw_ipv6.data()));
    }

    return XorMappedAddressAttribute{socket_address{address, port}};
  }

  bool XorMappedAddressAttribute::serialize_value(MessageBufferWriter &writer) const {
    const auto family = static_cast<Family>(address_.family());

    writer.write<uint8_t>(0);
    writer.write<uint8_t>(serialize_family(family));

    const auto port = address_.port();
    std::array<uint8_t, 2> raw_xport{};
    raw_xport[0] = (port >> 8) ^ 0x21;
    raw_xport[1] = port ^ 0x12;
    writer.write_raw(reinterpret_cast<const char *>(raw_xport.data()), 2);

    if (family == Family::Inet) {
      std::array<char, 4> raw_ipv4{};
      address_.addr().as_ipv4_address().write(raw_ipv4.data());

      std::array<uint8_t, 4> raw_xipv4{};
      raw_xipv4[0] = raw_ipv4[0] ^ 0x21;
      raw_xipv4[1] = raw_ipv4[1] ^ 0x12;
      raw_xipv4[2] = raw_ipv4[2] ^ 0xA4;
      raw_xipv4[3] = raw_ipv4[3] ^ 0x42;
      writer.write_raw(reinterpret_cast<const char *>(raw_xipv4.data()), 4);
    } else {
      std::array<char, 16> raw_ipv6{};
      address_.addr().as_ipv6_address().write(raw_ipv6.data());

      std::array<uint8_t, 16> raw_xipv6{};
      raw_xipv6[0] = raw_ipv6[0] ^ 0x21;
      raw_xipv6[1] = raw_ipv6[1] ^ 0x12;
      raw_xipv6[2] = raw_ipv6[2] ^ 0xA4;
      raw_xipv6[3] = raw_ipv6[3] ^ 0x42;
      for (auto i = 4; i < 16; ++i) raw_xipv6[i] = raw_ipv6[i] ^ writer.id()[i - 4];
      writer.write_raw(reinterpret_cast<const char *>(raw_xipv6.data()), 16);
    }

    return true;
  }

  UserhashAttribute::UserhashAttribute(const sstring &username, const sstring &realm) :
      FixedStringAttribute{type, LongTermAuthenticator::make_userhash(username, realm)} {}

  shared_ptr<MessageIntegrityAttribute> MessageIntegrityAttribute::dummy() {
    thread_local const auto dummy = ::make_shared<MessageIntegrityAttribute>(dummy_hash);
    return dummy;
  }

  bool MessageIntegrityAttribute::validate(const MessageBufferReader &reader, const std::vector<char> &key) const {
    HashContext context;
    return context.validate(*this, reader, key);
  }

  bool MessageIntegrityAttribute::serialize_value(MessageBufferWriter &writer) const {
    return serialize_message_integrity<MessageIntegrityAttribute>(writer);
  }

  shared_ptr<MessageIntegritySha256Attribute> MessageIntegritySha256Attribute::dummy() {
    thread_local const auto dummy = ::make_shared<MessageIntegritySha256Attribute>(dummy_hash);
    return dummy;
  }

  bool
  MessageIntegritySha256Attribute::validate(const MessageBufferReader &reader, const std::vector<char> &key) const {
    HashContext context;
    return context.validate(*this, reader, key);
  }

  bool MessageIntegritySha256Attribute::serialize_value(MessageBufferWriter &writer) const {
    return serialize_message_integrity<MessageIntegritySha256Attribute>(writer);
  }

  std::optional<FingerprintAttribute> FingerprintAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    if (length != sizeof(uint32_t)) return {};

    MS_GET(code, reader.read<uint32_t>(), std::nullopt)
    return FingerprintAttribute{*code};
  }

  bool FingerprintAttribute::verify(const MessageBufferReader &reader) const {
    if (!reader.fingerprint_pos() || !code_) return false;

    boost::crc_32_type crc;
    if (reader.header_buffer()) crc.process_bytes(reader.header_buffer()->get(), header_length);
    crc.process_bytes(reader.data(), *reader.fingerprint_pos());
    const auto code = crc.checksum() ^ fingerprint_xor;

    return code == *code_;
  }

  bool FingerprintAttribute::serialize_value(MessageBufferWriter &writer) const {
    writer.replace<uint16_t>(writer.current_size() - sizeof(uint16_t), sizeof(uint32_t));
    writer.write<uint32_t>(0);

    writer.replace_body_length();

    boost::crc_32_type crc;
    crc.process_bytes(writer.data(), writer.current_size() - 8);
    const auto code = crc.checksum() ^ fingerprint_xor;
    writer.replace<uint32_t>(writer.current_size() - sizeof(uint32_t), code);

    return true;
  }

  shared_ptr<ErrorCodeAttribute> ErrorCodeAttribute::TryAlternate() {
    thread_local const auto attribute = make_error(ErrorCode::TryAlternate);
    return attribute;
  }

  shared_ptr<ErrorCodeAttribute> ErrorCodeAttribute::BadRequest() {
    thread_local const auto attribute = make_error(ErrorCode::BadRequest);
    return attribute;
  }

  shared_ptr<ErrorCodeAttribute> ErrorCodeAttribute::Unauthenticated() {
    thread_local const auto attribute = make_error(ErrorCode::Unauthenticated);
    return attribute;
  }

  shared_ptr<ErrorCodeAttribute> ErrorCodeAttribute::UnknownAttribute() {
    thread_local const auto attribute = make_error(ErrorCode::UnknownAttribute);
    return attribute;
  }

  shared_ptr<ErrorCodeAttribute> ErrorCodeAttribute::StaleNonce() {
    thread_local const auto attribute = make_error(ErrorCode::StaleNonce);
    return attribute;
  }

  shared_ptr<ErrorCodeAttribute> ErrorCodeAttribute::ServerError() {
    thread_local const auto attribute = make_error(ErrorCode::ServerError);
    return attribute;
  }

  const std::vector<char> *ErrorCodeAttribute::get_reason_phrase(ErrorCode code) {
    static const std::map<ErrorCode, std::vector<char>> codes = {
        {ErrorCode::TryAlternate,     {'T', 'r', 'y', ' ', 'A', 'l', 't', 'e', 'r', 'n', 'a', 't', 'e'}},
        {ErrorCode::BadRequest,       {'B', 'a', 'd', ' ', 'R', 'e', 'q', 'u', 'e', 's', 't'}},
        {ErrorCode::Unauthenticated,  {'U', 'n', 'a', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'e', 'd'}},
        {ErrorCode::UnknownAttribute, {'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e'}},
        {ErrorCode::StaleNonce,       {'S', 't', 'a', 'l', 'e', ' ', 'N', 'o', 'n', 'c', 'e'}},
        {ErrorCode::ServerError,      {'S', 'e', 'r', 'v', 'e', 'r', ' ', 'E', 'r', 'r', 'o', 'r'}}
    };

    const auto it = codes.find(code);
    if (it == codes.cend()) return {};
    return &it->second;
  }

  std::optional<ErrorCodeAttribute> ErrorCodeAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    [[maybe_unused]] MS_GET(empty, reader.read<uint16_t>(), std::nullopt)

    MS_GET(cls, reader.read<uint8_t>(), std::nullopt)
    MS_GET(number, reader.read<uint8_t>(), std::nullopt)

    std::vector<char> reason_phrase;
    const auto reason_phrase_length = length - sizeof(uint32_t);
    if (reason_phrase_length) {
      if (reason_phrase_length > max_reason_phrase_length) return {};
      MS_GET(reason_phrase_ptr, reader.read_raw(length - sizeof(uint32_t)), std::nullopt)
      reason_phrase.insert(reason_phrase.cend(), reason_phrase_ptr, reason_phrase_ptr + reason_phrase_length);
    }

    const size_t code = (*cls & 0b111) * 100 + *number;
    if (code < min_error_code || code > max_error_code) return {};

    return ErrorCodeAttribute{static_cast<ErrorCode>(code), std::move(reason_phrase)};
  }

  bool ErrorCodeAttribute::serialize_value(MessageBufferWriter &writer) const {
    writer.write<uint16_t>(0);
    writer.write<uint8_t>(Utils::to_underlying(code_) / 100);
    writer.write<uint8_t>(Utils::to_underlying(code_) % 100);
    if (!reason_phrase_.empty()) writer.write_raw(reason_phrase_.data(), reason_phrase_.size());

    return true;
  }

  NonceAttribute::NonceAttribute(sstring nonce) : EscapedStringAttribute{type, std::move(nonce)} {
    feature_set_ = LongTermAuthenticator::parse_feature_set(string());
  }

  std::optional<PasswordAlgorithmsAttribute>
  PasswordAlgorithmsAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    if (!length) return {};

    std::vector<std::pair<PasswordAlgorithm, std::vector<char>>> algorithms;
    size_t read_bytes{};
    while (true) {
      if (read_bytes >= length) {
        if (read_bytes == length) break;
        else {
          MS_DEBUG("Expected {} bytes, read {} bytes", length, read_bytes);
          return {};
        }
      }

      MS_GET(algorithm, reader.read<uint16_t>(), std::nullopt)
      read_bytes += sizeof(uint16_t);

      MS_GET(parameters_length, reader.read<uint16_t>(), std::nullopt)
      read_bytes += sizeof(uint16_t);

      std::vector<char> parameters;
      if (*parameters_length) {
        MS_GET(parameters_ptr, reader.read_raw(*parameters_length), std::nullopt)
        read_bytes += *parameters_length;

        parameters.insert(parameters.cend(), parameters_ptr, parameters_ptr + *parameters_length);

        const auto padding = *parameters_length % 4 ? (4 - (*parameters_length % 4)) : 0;
        if (padding) {
          reader.skip(padding);
          read_bytes += padding;
        }
      }

      algorithms.emplace_back(static_cast<PasswordAlgorithm>(*algorithm), std::move(parameters));
    }

    return PasswordAlgorithmsAttribute{std::move(algorithms)};
  }

  bool PasswordAlgorithmsAttribute::serialize_value(MessageBufferWriter &writer) const {
    for (const auto &algorithm: algorithms_) {
      writer.write<uint16_t>(Utils::to_underlying(algorithm.first));
      writer.write<uint16_t>(algorithm.second.size());
      if (!algorithm.second.empty()) {
        writer.write_raw(algorithm.second.data(), algorithm.second.size());

        const auto padding = algorithm.second.size() % 4 ? (4 - (algorithm.second.size() % 4)) : 0;
        if (padding) writer.write_raw(padding_bytes.data(), padding);
      }
    }

    return true;
  }

  std::optional<PasswordAlgorithmAttribute>
  PasswordAlgorithmAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    size_t read_bytes{};

    MS_GET(algorithm, reader.read<uint16_t>(), std::nullopt)
    read_bytes += sizeof(uint16_t);

    MS_GET(parameters_length, reader.read<uint16_t>(), std::nullopt)
    read_bytes += sizeof(uint16_t);

    std::vector<char> parameters;
    size_t padding;
    if (*parameters_length) {
      MS_GET(parameters_ptr, reader.read_raw(*parameters_length), std::nullopt)
      read_bytes += *parameters_length;

      parameters.insert(parameters.cend(), parameters_ptr, parameters_ptr + *parameters_length);

      padding = *parameters_length % 4 ? (4 - (*parameters_length % 4)) : 0;
      if (padding) {
        reader.skip(padding);
        read_bytes += padding;
      }
    }

    if (read_bytes != length) return {};

    return PasswordAlgorithmAttribute{static_cast<PasswordAlgorithm>(*algorithm), std::move(parameters)};
  }

  bool PasswordAlgorithmAttribute::serialize_value(MessageBufferWriter &writer) const {
    writer.write<uint16_t>(Utils::to_underlying(algorithm_));
    writer.write<uint16_t>(parameters_.size());
    if (!parameters_.empty()) {
      writer.write_raw(parameters_.data(), parameters_.size());

      const auto padding = parameters_.size() % 4 ? (4 - (parameters_.size() % 4)) : 0;
      if (padding) writer.write_raw(padding_bytes.data(), padding);
    }

    return true;
  }

  /* Note: In [RFC3489], this field was padded to 32 by duplicating the last attribute. In this version of the
   * specification, the normal padding rules for attributes are used instead.
   */
  std::optional<UnknownAttributesAttribute>
  UnknownAttributesAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    if (!length) return {};

    std::vector<AttributeType> types;
    size_t read_bytes{};
    while (true) {
      if (read_bytes >= length) {
        if (read_bytes == length) break;
        else {
          MS_DEBUG("Expected {} bytes, read {} bytes", length, read_bytes);
          return {};
        }
      }

      MS_GET(t, reader.read<uint16_t>(), std::nullopt)
      read_bytes += sizeof(uint16_t);

      types.emplace_back(static_cast<AttributeType>(*t));
    }

    return UnknownAttributesAttribute{std::move(types)};
  }

  bool UnknownAttributesAttribute::serialize_value(MessageBufferWriter &writer) const {
    for (const auto t: types_) writer.write<uint16_t>(Utils::to_underlying(t));
    return true;
  }

  std::optional<AlternateServerAttribute>
  AlternateServerAttribute::parse_value(MessageBufferReader &reader, size_t length) {
    MS_GET(mapped_address, MappedAddressAttribute::parse_value(reader, length), std::nullopt)
    return AlternateServerAttribute{mapped_address->address()};
  }

  bool IncomprehensibleAttribute::serialize_value(MessageBufferWriter &writer) const {
    writer.write_raw(buffer_.data(), buffer_.size());
    return true;
  }
}
