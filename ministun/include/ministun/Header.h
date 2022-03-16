#pragma once

#include <stddef.h>
#include <stdint.h>
#include <array>
#include <optional>
#include <utility>
#include <seastar/net/byteorder.hh>
#include <ministun/Buffer.h>
#include <ministun/Types.h>

namespace ms {
  struct NetworkHeader {
    seastar::net::packed<uint16_t> type;
    seastar::net::packed<uint16_t> length;
    seastar::net::packed<uint32_t> magic_cookie;
    char id[12];

    template<class Adjuster>
    auto adjust_endianness(Adjuster a) {
      return a(type, length, magic_cookie);
    }
  } __attribute__((packed));

  class Header final {
  public:
    static std::optional<std::pair<Header, uint16_t>> parse(BufferReader &reader);

    Header(Method method, Class cls);

    Header(Method method, Class cls, const Id &id) :
        method_{method}, class_{cls}, id_{id} {}

    Method method() const { return method_; }

    Class cls() const { return class_; }

    const Id &id() const { return id_; }

    void serialize(MessageBufferWriter &writer) const;

  private:
    Method method_;
    Class class_;
    Id id_;
  };
}
