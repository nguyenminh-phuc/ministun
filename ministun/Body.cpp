#include <ministun/Body.h>

using namespace seastar;

namespace ms {
  std::optional<Body> Body::parse(MessageBufferReader &reader, size_t length, bool verify_fingerprint) {
    Body body;

    while (true) {
      const auto current_pos = reader.pos();
      if (current_pos >= length) {
        if (current_pos == length) break;
        else {
          MS_DEBUG("Expected {} bytes, read {} bytes", length, current_pos);
          return {};
        }
      }

      MS_GET(attribute, Attribute::parse(reader), std::nullopt)
      if (body.add(attribute)) {
        switch (attribute->type()) {
          case AttributeType::MessageIntegrity:
            reader.set_message_integrity_pos(current_pos);
            break;
          case AttributeType::MessageIntegritySha256:
            reader.set_message_integrity_sha256_pos(current_pos);
            break;
          case AttributeType::Fingerprint:
            reader.set_fingerprint_pos(current_pos);
            break;
          default:;
        }
      }
    }

    if (verify_fingerprint) {
      if (auto fingerprint = body.find<FingerprintAttribute>()) {
        if (!fingerprint->verify(reader)) {
          MS_DEBUG("Failed to verify fingerprint {:#X}", *fingerprint->code());
          return {};
        }
      }
    }

    return body;
  }

  /* The FINGERPRINT Attribute MUST be the last Attribute in the Message and thus will appear after MESSAGE-INTEGRITY
   * and MESSAGE-INTEGRITY-SHA256.
   *
   * Note that agents MUST ignore all attributes that follow MESSAGE-INTEGRITY, with the exception of the
   * MESSAGE-INTEGRITY-SHA256 and FINGERPRINT attributes.
   * Similarly, agents MUST ignore all attributes that follow the MESSAGE-INTEGRITY-SHA256 Attribute if the
   * MESSAGE-INTEGRITY Attribute is not present, with the exception of the FINGERPRINT Attribute.
   *
   * Should the order be like this: normal attributes -> message integrity -> message integrity sha256 -> fingerprint
   */
  bool Body::add(shared_ptr<Attribute> attribute) {
    if (!attribute) return false;

    switch (attribute->type()) {
      case AttributeType::MessageIntegrity:
        if (message_integrity_index_ || message_integrity_sha256_index_ || fingerprint_index_) return false;
        message_integrity_index_ = attributes_.size();
        break;
      case AttributeType::MessageIntegritySha256:
        if (message_integrity_sha256_index_ || fingerprint_index_) return false;
        message_integrity_sha256_index_ = attributes_.size();
        break;
      case AttributeType::Fingerprint:
        if (fingerprint_index_) return false;
        fingerprint_index_ = attributes_.size();
        break;
      default:
        if (message_integrity_index_ || message_integrity_sha256_index_ || fingerprint_index_) return false;
    }

    attributes_.emplace_back(std::move(attribute));
    return true;
  }

  bool Body::serialize(MessageBufferWriter &writer) const {
    for (const auto &attribute: attributes_) {
      BOOST_ASSERT(attribute);

      const auto attribute_pos = writer.current_size();
      if (!attribute->serialize(writer)) return false;

      const auto attribute_with_padding_length = writer.current_size() - attribute_pos;
      if (attribute_with_padding_length % 4 != 0) return false;
    }

    return true;
  }
}
