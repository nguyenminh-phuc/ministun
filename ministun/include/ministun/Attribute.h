#pragma once

#include <stddef.h>
#include <algorithm>
#include <array>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/inet_address.hh>
#include <seastar/net/socket_defs.hh>
#include <ministun/Buffer.h>
#include <ministun/Types.h>
#include <ministun/Utils.h>

namespace ms {
  class Attribute {
  public:
    static seastar::shared_ptr<Attribute> parse(MessageBufferReader &reader);

    Attribute(AttributeType type) : type_{type} {}

    virtual ~Attribute() = default;

    AttributeType type() const { return type_; }

    bool serialize(MessageBufferWriter &writer);

    virtual bool serialize_value(MessageBufferWriter &writer) const = 0;

  private:
    AttributeType type_;
  };

  class ArbitraryStringAttribute : public Attribute {
  public:
    static seastar::shared_ptr<ArbitraryStringAttribute>
    parse_value(BufferReader &reader, size_t length, AttributeType type);

    const seastar::sstring &string() const { return string_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  protected:
    ArbitraryStringAttribute(AttributeType type, seastar::sstring string) :
        Attribute{type}, string_{std::move(string)} {
      BOOST_ASSERT(!string_.empty());
    }

  private:
    seastar::sstring string_;
  };

  /* It contains a sequence of qdtext or quoted-pair, which are defined in [RFC3261].
   * qdtext = LWS / %x21 / %x23-5B / %x5D-7E / UTF8-NONASCII
   * quoted-pair = "\" (%x00-09 / %x0B-0C / %x0E-7F)
   */
  class EscapedStringAttribute : public ArbitraryStringAttribute {
  public:
    static seastar::shared_ptr<EscapedStringAttribute>
    parse_value(BufferReader &reader, size_t length, AttributeType type);

  protected:
    EscapedStringAttribute(AttributeType type, seastar::sstring string) :
        ArbitraryStringAttribute{type, std::move(string)} {}
  };

  template<size_t size>
  class FixedStringAttribute : public Attribute {
  public:
    template<class T>
    static seastar::shared_ptr<T> parse_value(MessageBufferReader &reader, size_t length) {
      static_assert(std::is_base_of<FixedStringAttribute<size>, T>::value);

      if (length != size) return {};
      MS_GET(data, reader.read_raw(length), nullptr)

      std::array<char, size> string{};
      std::copy_n(data, length, string.data());
      return seastar::make_shared<T>(string);
    }

    const std::array<char, size> &string() const { return string_; }

    bool serialize_value(MessageBufferWriter &writer) const override {
      writer.write_raw(string_.data(), size);
      return true;
    }

  protected:
    FixedStringAttribute(AttributeType type, const std::array<char, size> &string) :
        Attribute{type}, string_{string} {}

  private:
    std::array<char, size> string_;
  };

  class MappedAddressAttribute : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::MappedAddress;

    static std::optional<MappedAddressAttribute> parse_value(MessageBufferReader &reader, size_t length);

    MappedAddressAttribute(const seastar::socket_address &address) : Attribute{type}, address_{address} {}

    const seastar::socket_address &address() const { return address_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  protected:
    MappedAddressAttribute(AttributeType t, const seastar::socket_address &address) : Attribute{t}, address_{address} {}

  private:
    seastar::socket_address address_;
  };

  class XorMappedAddressAttribute final : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::XorMappedAddress;

    static std::optional<XorMappedAddressAttribute> parse_value(MessageBufferReader &reader, size_t length);

    XorMappedAddressAttribute(const seastar::socket_address &address) : Attribute{type}, address_{address} {}

    const seastar::socket_address &address() const { return address_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    seastar::socket_address address_;
  };

  class UsernameAttribute final : public ArbitraryStringAttribute {
  public:
    static constexpr AttributeType type = AttributeType::Username;

    UsernameAttribute(seastar::sstring username) : ArbitraryStringAttribute{type, std::move(username)} {}
  };

  class UserhashAttribute final : public FixedStringAttribute<32> {
  public:
    static constexpr AttributeType type = AttributeType::Userhash;

    UserhashAttribute(const std::array<char, 32> &userhash) : FixedStringAttribute{type, userhash} {}

    UserhashAttribute(const seastar::sstring &username, const seastar::sstring &realm);
  };

  class MessageIntegrityAttribute final : public FixedStringAttribute<20> {
  public:
    static constexpr AttributeType type = AttributeType::MessageIntegrity;
    static constexpr std::array<char, 20> dummy_hash{};

    static seastar::shared_ptr<MessageIntegrityAttribute> dummy();

    MessageIntegrityAttribute(const std::array<char, 20> &hash) : FixedStringAttribute{type, hash} {}

    bool validate(const MessageBufferReader &reader, const std::vector<char> &key) const;

    bool serialize_value(MessageBufferWriter &writer) const override;
  };

  // TODO(optional)
  // A usage also defines: If MESSAGE-INTEGRITY-SHA256 truncation is permitted, and the limits permitted for truncation.
  class MessageIntegritySha256Attribute final : public FixedStringAttribute<32> {
  public:
    static constexpr AttributeType type = AttributeType::MessageIntegritySha256;
    static constexpr std::array<char, 32> dummy_hash{};

    static seastar::shared_ptr<MessageIntegritySha256Attribute> dummy();

    MessageIntegritySha256Attribute(const std::array<char, 32> &hash) : FixedStringAttribute{type, hash} {}

    bool validate(const MessageBufferReader &reader, const std::vector<char> &key) const;

    bool serialize_value(MessageBufferWriter &writer) const override;
  };

  class FingerprintAttribute final : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::Fingerprint;

    static std::optional<FingerprintAttribute> parse_value(MessageBufferReader &reader, size_t length);

    FingerprintAttribute() : Attribute{type} {}

    FingerprintAttribute(uint32_t code) : Attribute{AttributeType::Fingerprint}, code_{code} {}

    std::optional<uint32_t> code() const { return code_; }

    bool verify(const MessageBufferReader &reader) const;

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    std::optional<uint32_t> code_;
  };

  /* A STUN error code is a number in the range 0-699.
   * The ERROR-CODE attribute contains a numeric error code value in the range of 300 to 699
   */
  class ErrorCodeAttribute final : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::PasswordAlgorithm;

    static seastar::shared_ptr<ErrorCodeAttribute> TryAlternate();

    static seastar::shared_ptr<ErrorCodeAttribute> BadRequest();

    static seastar::shared_ptr<ErrorCodeAttribute> Unauthenticated();

    static seastar::shared_ptr<ErrorCodeAttribute> UnknownAttribute();

    static seastar::shared_ptr<ErrorCodeAttribute> StaleNonce();

    static seastar::shared_ptr<ErrorCodeAttribute> ServerError();

    static const std::vector<char> *get_reason_phrase(ErrorCode code);

    static std::optional<ErrorCodeAttribute> parse_value(MessageBufferReader &reader, size_t length);

    ErrorCodeAttribute(ErrorCode code, std::vector<char> reason_phrase = {}) :
        Attribute{type}, code_{code}, reason_phrase_{std::move(reason_phrase)} {}

    ErrorCode code() const { return code_; }

    const std::vector<char> &reason_phrase() const { return reason_phrase_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    ErrorCode code_;
    std::vector<char> reason_phrase_;
  };

  class RealmAttribute final : public EscapedStringAttribute {
  public:
    static constexpr AttributeType type = AttributeType::Realm;

    RealmAttribute(seastar::sstring realm) : EscapedStringAttribute{type, std::move(realm)} {}
  };

  class NonceAttribute final : public EscapedStringAttribute {
  public:
    static constexpr AttributeType type = AttributeType::Nonce;

    NonceAttribute(seastar::sstring nonce);

    std::optional<SecurityFeatureSet> feature_set() const { return feature_set_; }

  private:
    std::optional<SecurityFeatureSet> feature_set_;
  };

  class PasswordAlgorithmsAttribute final : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::PasswordAlgorithms;

    static std::optional<PasswordAlgorithmsAttribute> parse_value(MessageBufferReader &reader, size_t length);

    PasswordAlgorithmsAttribute(std::vector<std::pair<PasswordAlgorithm, std::vector<char>>> algorithms) :
        Attribute{type}, algorithms_{std::move(algorithms)} {
      BOOST_ASSERT(!algorithms_.empty());
    }

    const std::vector<std::pair<PasswordAlgorithm, std::vector<char>>> &algorithms() const { return algorithms_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    std::vector<std::pair<PasswordAlgorithm, std::vector<char>>> algorithms_;
  };

  class PasswordAlgorithmAttribute final : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::PasswordAlgorithm;

    static std::optional<PasswordAlgorithmAttribute> parse_value(MessageBufferReader &reader, size_t length);

    PasswordAlgorithmAttribute(PasswordAlgorithm algorithm, std::vector<char> parameters) :
        Attribute{type}, algorithm_{algorithm}, parameters_{std::move(parameters)} {}

    PasswordAlgorithm algorithm() const { return algorithm_; }

    const std::vector<char> &parameters() const { return parameters_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    PasswordAlgorithm algorithm_;
    std::vector<char> parameters_;
  };

  class UnknownAttributesAttribute final : public Attribute {
  public:
    static constexpr AttributeType type = AttributeType::UnknownAttributes;

    static std::optional<UnknownAttributesAttribute> parse_value(MessageBufferReader &reader, size_t length);

    UnknownAttributesAttribute(std::vector<AttributeType> types) : Attribute{type}, types_{std::move(types)} {
      BOOST_ASSERT(!types_.empty());
    }

    const std::vector<AttributeType> &types() const { return types_; }

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    std::vector<AttributeType> types_;
  };

  class SoftwareAttribute final : public ArbitraryStringAttribute {
  public:
    static constexpr AttributeType type = AttributeType::Software;

    SoftwareAttribute(seastar::sstring software) : ArbitraryStringAttribute{type, std::move(software)} {}
  };

  class AlternateServerAttribute final : public MappedAddressAttribute {
  public:
    static constexpr AttributeType type = AttributeType::AlternateServer;

    static std::optional<AlternateServerAttribute> parse_value(MessageBufferReader &reader, size_t length);

    AlternateServerAttribute(const seastar::socket_address &server) : MappedAddressAttribute{type, server} {}
  };

  class AlternateDomainAttribute final : public ArbitraryStringAttribute {
  public:
    static constexpr AttributeType type = AttributeType::AlternateDomain;

    AlternateDomainAttribute(seastar::sstring domain) : ArbitraryStringAttribute{type, std::move(domain)} {}
  };

  class IncomprehensibleAttribute final : public Attribute {
  public:
    IncomprehensibleAttribute(AttributeType type, std::vector<char> buffer) :
        Attribute{type}, buffer_{std::move(buffer)} {}

    bool serialize_value(MessageBufferWriter &writer) const override;

  private:
    std::vector<char> buffer_;
  };
}
