#pragma once

#include <limits.h>
#include <stddef.h>
#include <algorithm>
#include <array>
#include <optional>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/sstring.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/byteorder.hh>
#include <ministun/Types.h>

static_assert(CHAR_BIT == 8);

namespace ms {
  template<size_t size>
  struct FixedBuffer {
    std::array<char, size> data;
    size_t current_size;
  };

  using Id = std::array<char, 12>;
  using MessageBuffer = FixedBuffer<max_message_length>;

  class BufferReader {
  public:
    BufferReader(seastar::temporary_buffer<char> &buffer, size_t pos = 0) : buffer_{buffer.share()}, pos_{pos} {}

    virtual ~BufferReader() = default;

    BufferReader(BufferReader &&reader) noexcept: buffer_{reader.buffer_.share()}, pos_{reader.pos_} {}

    size_t size() const { return buffer_.size(); }

    size_t pos() const { return pos_; }

    const char *data() const { return buffer_.get(); }

    void skip(size_t size) {
      BOOST_ASSERT(size);
      pos_ += size;
    }

    const char *read_raw(size_t size) {
      if (!size || pos_ + size - 1 >= buffer_.size()) return {};

      const auto value_pos = pos_;
      pos_ += size;
      return buffer_.get() + value_pos;
    }

    template<typename T>
    std::optional<T> read() {
      const auto data = read_raw(sizeof(T));
      if (!data) return {};
      return seastar::net::ntoh(*reinterpret_cast<const T *>(data));
    }

  private:
    seastar::temporary_buffer<char> buffer_;
    size_t pos_;
  };

  class MessageBufferReader final : public BufferReader {
  public:
    MessageBufferReader(seastar::temporary_buffer<char> &message_buffer) : BufferReader{message_buffer} {}

    MessageBufferReader(
        seastar::temporary_buffer<char> &header_buffer, const Id &id,
        seastar::temporary_buffer<char> &body_buffer) :
        BufferReader{body_buffer}, id_{id}, header_buffer_{header_buffer.share()} {
      if (header_buffer) BOOST_ASSERT(header_buffer.size() == header_length);
    }

    const std::optional<seastar::temporary_buffer<char>> &header_buffer() const { return header_buffer_; }

    const Id &id() const {
      BOOST_ASSERT(id_);
      return *id_;
    }

    std::optional<size_t> message_integrity_pos() const { return message_integrity_pos_; }

    std::optional<size_t> message_integrity_sha256_pos() const { return message_integrity_sha256_pos_; }

    std::optional<size_t> fingerprint_pos() const { return fingerprint_pos_; }

    void set_id(const Id &id) { id_ = id; }

    void set_message_integrity_pos(size_t pos) { message_integrity_pos_ = pos; }

    void set_message_integrity_sha256_pos(size_t pos) { message_integrity_sha256_pos_ = pos; }

    void set_fingerprint_pos(size_t pos) { fingerprint_pos_ = pos; }

  private:
    std::optional<Id> id_;
    std::optional<seastar::temporary_buffer<char>> header_buffer_;
    std::optional<size_t> message_integrity_pos_;
    std::optional<size_t> message_integrity_sha256_pos_;
    std::optional<size_t> fingerprint_pos_;
  };

  template<size_t size>
  class FixedBufferWriter {
  public:
    FixedBufferWriter() : buffer_{} {};

    virtual ~FixedBufferWriter() = default;

    const FixedBuffer<size> &buffer() const { return buffer_; }

    size_t current_size() const { return buffer_.current_size; }

    char *data() { return buffer_.data.data(); }

    void write_raw(const char *buffer, size_t buffer_size) {
      BOOST_ASSERT(buffer && buffer_size);
      std::copy_n(buffer, buffer_size, buffer_.data.data() + buffer_.current_size);
      buffer_.current_size += buffer_size;
    }

    void replace_raw(size_t pos, const char *buffer, size_t buffer_size) {
      BOOST_ASSERT(buffer && buffer_size && pos + buffer_size - 1 < buffer_.current_size);
      std::copy_n(buffer, buffer_size, buffer_.data.data() + pos);
    }

    template<class T>
    void write(T value) {
      const auto network_value = seastar::net::hton(value);
      write_raw(reinterpret_cast<const char *>(&network_value), sizeof(T));
    }

    template<class T>
    void replace(size_t pos, T value) {
      const auto network_value = seastar::net::hton(value);
      replace_raw(pos, reinterpret_cast<const char *>(&network_value), sizeof(T));
    }

  private:
    FixedBuffer<size> buffer_;
  };

  class MessageBufferWriter final : public FixedBufferWriter<max_message_length> {
  public:
    MessageBufferWriter(const Id &id) : id_{id} {}

    const Id &id() const { return id_; }

    const std::optional<std::vector<char>> &key() const { return key_; }

    void set_key(const std::vector<char> &key) {
      BOOST_ASSERT(!key.empty());
      key_ = key;
    }

    void mark_body_length_pos() { body_length_pos_ = current_size(); }

    void replace_body_length() {
      BOOST_ASSERT(body_length_pos_ && current_size() >= header_length);
      replace<uint16_t>(*body_length_pos_, current_size() - header_length);
    }

  private:
    std::optional<size_t> body_length_pos_;
    Id id_;
    std::optional<std::vector<char>> key_;
  };
}
