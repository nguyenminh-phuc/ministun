#pragma once

#include <array>
#include <optional>
#include <utility>
#include <seastar/core/temporary_buffer.hh>
#include <ministun/Attribute.h>
#include <ministun/Body.h>
#include <ministun/Buffer.h>
#include <ministun/Header.h>
#include <ministun/Types.h>

namespace ms {
  class Message final {
  public:
    static std::optional<Message> parse(MessageBufferReader &message_reader, bool verify_fingerprint = true);

    Message(const Header &header, Body body = {}) : header_{header}, body_{std::move(body)} {}

    Method method() const { return header_.method(); }

    Class cls() const { return header_.cls(); }

    const Id &id() const { return header_.id(); }

    const std::vector<seastar::shared_ptr<Attribute>> &attributes() const { return body_.attributes(); }

    template<class T>
    seastar::shared_ptr<T> find() const { return body_.find<T>(); }

    bool add(seastar::shared_ptr<Attribute> attribute) { return body_.add(std::move(attribute)); }

    bool serialize(MessageBufferWriter &writer) const;

  private:
    Header header_;
    Body body_;
  };
}
