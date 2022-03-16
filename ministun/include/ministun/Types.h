#pragma once

#include <stddef.h>
#include <stdint.h>
#include <array>
#include <optional>
#include <string_view>
#include <sys/socket.h>
#include <seastar/net/inet_address.hh>

namespace ms {
  /* For IPv4, the actual STUN Message would need to be less than 548 bytes
   * (576 minus 20-byte IP Header, minus 8-byte UDP Header, assuming no IP options are used).
   *
   * I think 544 bytes ought to be enough for STUN messages.
   */
  static constexpr size_t max_message_length = 544;
  static constexpr size_t header_length = 20;
  static constexpr size_t max_body_length = max_message_length - header_length;
  static constexpr size_t max_attribute_value_length = max_body_length - sizeof(uint32_t);

  static constexpr uint32_t magic_cookie = 0x2112A442;
  static constexpr std::string_view nonce_cookie = "obMatJos2";

  static constexpr size_t max_username_length = 508;
  static constexpr uint32_t fingerprint_xor = 0x5354554E;
  static constexpr size_t min_error_code = 300;
  static constexpr size_t max_error_code = 699;
  static constexpr size_t max_reason_phrase_length = 127;
  static constexpr size_t max_realm_length = 127;
  static constexpr size_t max_nonce_length = 127;
  static constexpr size_t max_software_length = 127;
  static constexpr size_t max_alternate_domain_length = 255;
  static constexpr size_t feature_set_length = 3;
  static constexpr size_t encoded_feature_set_length = 4;

  enum class Method {
    Binding = 0b0000'0000'0001
  };

  enum class Class {
    Request = 0b00,
    Indication = 0b01,
    SuccessResponse = 0b10,
    ErrorResponse = 0b11
  };

  enum class AttributeType : uint16_t {
    // Comprehension-required
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    Realm = 0x0014,
    Nonce = 0x0015,
    MessageIntegritySha256 = 0x001C,
    PasswordAlgorithm = 0x001D,
    Userhash = 0x001E,
    XorMappedAddress = 0x0020,

    // Comprehension-optional
    PasswordAlgorithms = 0x8002,
    AlternateDomain = 0x8003,
    Software = 0x8022,
    AlternateServer = 0x8023,
    Fingerprint = 0x8028
  };

  enum class ErrorCode {
    TryAlternate = 300,
    BadRequest = 400,
    Unauthenticated = 401,
    UnknownAttribute = 420,
    StaleNonce = 438,
    ServerError = 500
  };

  enum class PasswordAlgorithm : uint16_t {
    Md5 = 0x0001,
    Sha256 = 0x002
  };

  enum class CredentialMechanism {
    ShortTerm,
    LongTerm
  };

  enum class IntegrityAlgorithm {
    Sha1,
    Sha256
  };

  struct SecurityFeatureSet final {
    bool password_algorithms;
    bool username_anonymity;
  };

  enum class Family : sa_family_t {
    Inet = static_cast<sa_family_t>(seastar::net::inet_address::family::INET),
    Inet6 = static_cast<sa_family_t>(seastar::net::inet_address::family::INET6)
  };

  enum class Protocol {
    Udp,
    Tcp
  };

  enum class Service {
    Stun,
    Stuns
  };

  static constexpr std::array<std::string_view, 2> protocol_strs = {
      "udp",
      "tcp"
  };

  static constexpr std::array<std::string_view, 2> service_strs = {
      "stun",
      "stuns"
  };

  static constexpr std::array<uint16_t, 2> service_default_ports = {
      3478,
      5349
  };

  static constexpr std::optional<Family> family_from_string(std::string_view string) {
    if (string == "4") return Family::Inet;
    else if (string == "6") return Family::Inet6;
    return {};
  }

  static constexpr std::optional<Protocol> protocol_from_string(std::string_view string) {
    if (string == "udp") return Protocol::Udp;
    else if (string == "tcp") return Protocol::Tcp;
    return {};
  }

  static constexpr std::optional<Service> service_from_string(std::string_view string) {
    if (string == "stun") return Service::Stun;
    else if (string == "stuns") return Service::Stuns;
    return {};
  }
}
