#include <ministun/Message.h>
#include <stdint.h>
#include <ministun/Types.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  std::optional<Message> Message::parse(MessageBufferReader &message_reader, bool verify_fingerprint) {
    if (message_reader.size() < header_length || message_reader.size() > max_message_length) return {};

    MS_GET(pair, Header::parse(message_reader), std::nullopt)
    const auto header = pair->first;
    const auto body_length = pair->second;

    if (!body_length) return Message{header};

    message_reader.set_id(header.id());
    MS_GET(body, Body::parse(message_reader, header_length + body_length, verify_fingerprint), std::nullopt)
    return Message{header, std::move(*body)};
  }

  bool Message::serialize(MessageBufferWriter &writer) const {
    header_.serialize(writer);

    if (!body_.serialize(writer)) return false;
    writer.replace_body_length();

    return true;
  }
}
