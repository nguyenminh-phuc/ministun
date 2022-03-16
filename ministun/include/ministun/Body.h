#pragma once

#include <stddef.h>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/shared_ptr.hh>
#include <ministun/Attribute.h>
#include <ministun/Buffer.h>

namespace ms {
  class Body final {
  public:
    static std::optional<Body> parse(MessageBufferReader &reader, size_t length, bool verify_fingerprint = true);

    const std::vector<seastar::shared_ptr<Attribute>> &attributes() const { return attributes_; }

    bool serialize(MessageBufferWriter &writer) const;

    template<class T>
    seastar::shared_ptr<T> find() const {
      static_assert(std::is_base_of<Attribute, T>::value);

      if constexpr (std::is_same<MessageIntegritySha256Attribute, T>::value) {
        if (!message_integrity_sha256_index_) return {};
        return dynamic_pointer_cast<MessageIntegritySha256Attribute>(attributes_[*message_integrity_sha256_index_]);
      } else if constexpr (std::is_same<MessageIntegrityAttribute, T>::value) {
        if (!message_integrity_index_) return {};
        return dynamic_pointer_cast<MessageIntegrityAttribute>(attributes_[*message_integrity_index_]);
      } else if constexpr (std::is_same<FingerprintAttribute, T>::value) {
        if (!fingerprint_index_) return {};
        return dynamic_pointer_cast<FingerprintAttribute>(attributes_[*fingerprint_index_]);
      } else {
        for (const auto &attribute: attributes_) {
          BOOST_ASSERT(attribute);
          if (attribute->type() == T::type) return seastar::dynamic_pointer_cast<T>(attribute);
        }

        return {};
      }
    }

    bool add(seastar::shared_ptr<Attribute> attribute);

  private:
    std::vector<seastar::shared_ptr<Attribute>> attributes_;
    std::optional<size_t> message_integrity_index_;
    std::optional<size_t> message_integrity_sha256_index_;
    std::optional<size_t> fingerprint_index_;
  };
}
