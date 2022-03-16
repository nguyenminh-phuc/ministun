#include <ministun/Header.h>
#include <algorithm>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  /* It checks that the first two bits are 0, that the Magic Cookie field has the correct value, that the Message length
   * is sensible, and that the Method value is a supported Method. It checks that the Message class is allowed
   * for the particular Method. If the Message class is "Success Response" or "Error Response", the agent checks that
   * the transaction ID matches a transaction that is still in progress. If the FINGERPRINT extension is being used,
   * the agent checks that the FINGERPRINT Attribute is present and contains the correct value. If any errors
   * are detected, the Message is silently discarded. In the case when STUN is being multiplexed with another Protocol,
   * an error may indicate that this is not really a STUN Message; in this case, the agent should try to parse
   * the Message as a different Protocol.
   *
   * Since all STUN attributes are padded to a multiple of 4 bytes, the last 2 bits of this field are always zero.
   * This provides another way to distinguish STUN packets from packets of other protocols.
   */
  std::optional<std::pair<Header, uint16_t>> Header::parse(BufferReader &reader) {
    MS_GET(raw_header, reader.read_raw(header_length), std::nullopt)
    NetworkHeader raw{net::ntoh(*reinterpret_cast<const NetworkHeader *>(raw_header))};

    if ((raw.type & 0b1100'0000'0000'0000) != 0) return {};
    if (raw.length > max_body_length || (raw.length & 0b11)) return {};
    if (raw.magic_cookie != magic_cookie) return {};

    Id id{};
    std::copy_n(raw.id, 12, id.begin());

    const auto m11_7 = (raw.type & 0b1111'1000'0000) >> 2;
    const auto m6_4 = (raw.type & 0b111'0000) >> 1;
    const auto m3_0 = raw.type & 0b1111;
    const auto method = static_cast<Method>(m11_7 | m6_4 | m3_0);

    const auto c0 = (raw.type & 0b1'0000) >> 4;
    const auto c1 = (raw.type & 0b1'0001'0000) >> 7;
    const auto class_int = c1 | c0;
    const auto cls = static_cast<Class>(class_int);

    return std::make_pair(Header{method, cls, id}, raw.length);
  }

  Header::Header(Method method, Class cls) : method_{method}, class_{cls}, id_{} {
    for (size_t i = 0; i < 12; ++i)
      id_[i] = Utils::random();
  }

  void Header::serialize(MessageBufferWriter &writer) const {
    const auto m11_7 = (Utils::to_underlying(method_) & 0b1111'1000'0000) << 2;
    const auto m6_4 = (Utils::to_underlying(method_) & 0b111'0000) << 1;
    const auto m3_0 = Utils::to_underlying(method_) & 0b1111;
    const auto class_int = Utils::to_underlying(class_);
    const auto c1 = (class_int & 0b10) << 7;
    const auto c0 = (class_int & 0b1) << 4;
    const auto type = m11_7 | c1 | m6_4 | c0 | m3_0;
    writer.write<uint16_t>(type);

    writer.mark_body_length_pos();
    writer.write<uint16_t>(0);

    writer.write<uint32_t>(magic_cookie);
    writer.write_raw(id().data(), 12);
  }
}
