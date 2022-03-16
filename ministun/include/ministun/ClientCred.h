#pragma once

#include <optional>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <ministun/Attribute.h>
#include <ministun/Buffer.h>
#include <ministun/Message.h>
#include <ministun/Types.h>

namespace ms {
  class ClientCred {
  public:
    enum class Result {
      Success,
      Error,
      Retry
    };

    ClientCred(CredentialMechanism mechanism) : mechanism_{mechanism} {}

    virtual ~ClientCred() = default;

    CredentialMechanism mechanism() const { return mechanism_; }

    virtual void apply_auth(MessageBufferWriter &request_writer, Message &request) const = 0;

    virtual Result validate_auth(const MessageBufferReader &response_reader, Message &response) = 0;

  private:
    CredentialMechanism mechanism_;
  };

  class ShortTermClientCred final : public ClientCred {
  public:
    ShortTermClientCred(seastar::sstring username, const std::vector<char> &password);

    ShortTermClientCred(seastar::sstring username, const std::vector<char> &password, IntegrityAlgorithm algorithm);

    void apply_auth(MessageBufferWriter &request_writer, Message &request) const override;

    Result validate_auth(const MessageBufferReader &response_reader, Message &response) override;

  private:
    seastar::sstring username_;
    std::vector<char> key_;
    std::optional<IntegrityAlgorithm> algorithm_;
  };

  class LongTermClientCred final : public ClientCred {
  public:
    LongTermClientCred(seastar::sstring username, std::vector<char> password) :
        ClientCred{CredentialMechanism::LongTerm},
        username_{std::move(username)}, password_{std::move(password)}, error_in_last_response_{} {
      BOOST_ASSERT(!username_.empty() && !password_.empty());
    }

    void apply_auth(MessageBufferWriter &request_writer, Message &request) const override;

    Result validate_auth(const MessageBufferReader &response_reader, Message &response) override;

  private:
    struct Cache {
      seastar::sstring realm;
      seastar::sstring nonce;
      std::vector<char> key;
      std::optional<SecurityFeatureSet> feature_set;
      seastar::shared_ptr<PasswordAlgorithmsAttribute> algorithms;
      seastar::shared_ptr<PasswordAlgorithmAttribute> algorithm;
    };

    seastar::sstring username_;
    std::vector<char> password_;
    std::optional<Cache> cache_;
    bool error_in_last_response_;
  };
}
