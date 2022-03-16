#pragma once

#include <stddef.h>
#include <time.h>
#include <array>
#include <chrono>
#include <map>
#include <optional>
#include <utility>
#include <vector>
#include <boost/assert.hpp>
#include <seastar/core/lowres_clock.hh>
#include <seastar/core/metrics.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/socket_defs.hh>
#include <ministun/Attribute.h>
#include <ministun/Buffer.h>
#include <ministun/Message.h>
#include <ministun/Types.h>

namespace ms {
  struct AuthInput final {
    const seastar::socket_address &remote_address;
    const MessageBufferReader &request_reader;
    const Message &request;
  };

  class AuthResult {
  public:
    enum class Type {
      Success,
      Error
    };

    virtual ~AuthResult() = default;

    Type type() const { return type_; }

    const std::vector<seastar::shared_ptr<Attribute>> &attributes() const { return attributes_; }

  protected:
    AuthResult(Type type) : type_{type} {}

    AuthResult(Type type, std::vector<seastar::shared_ptr<Attribute>> attributes) :
        type_{type}, attributes_{std::move(attributes)} {
      BOOST_ASSERT(!attributes_.empty());
    }

  private:
    Type type_;
    std::vector<seastar::shared_ptr<Attribute>> attributes_;
  };

  class SuccessAuthResult final : public AuthResult {
  public:
    SuccessAuthResult(IntegrityAlgorithm algorithm, std::vector<char> key) :
        AuthResult{Type::Success}, algorithm_{algorithm}, key_{std::move(key)} {
      BOOST_ASSERT(!key_.empty());
    }

    SuccessAuthResult(
        std::vector<seastar::shared_ptr<Attribute>> attributes,
        IntegrityAlgorithm algorithm, std::vector<char> key) :
        AuthResult{Type::Success, std::move(attributes)}, algorithm_{algorithm}, key_{std::move(key)} {
      BOOST_ASSERT(!key_.empty());
    }

    IntegrityAlgorithm algorithm() const { return algorithm_; }

    const std::vector<char> &key() const { return key_; }

  private:
    IntegrityAlgorithm algorithm_;
    std::vector<char> key_;
  };

  class ErrorAuthResult final : public AuthResult {
  public:
    ErrorAuthResult(seastar::shared_ptr<ErrorCodeAttribute> attribute) :
        AuthResult{Type::Error, std::vector<seastar::shared_ptr<Attribute>>{std::move(attribute)}} {}

    ErrorAuthResult(std::vector<seastar::shared_ptr<Attribute>> attributes) :
        AuthResult{Type::Error, std::move(attributes)} {}
  };

  class Authenticator {
  public:
    Authenticator(CredentialMechanism mechanism);

    virtual ~Authenticator() = default;

    CredentialMechanism mechanism() const { return mechanism_; }

    virtual seastar::future<> stop() { return seastar::make_ready_future<>(); };

    seastar::future<seastar::shared_ptr<AuthResult>> check(const AuthInput &result);

  protected:
    static bool validate_integrity(const AuthInput &input, const std::vector<char> &key, IntegrityAlgorithm &algorithm);

    virtual seastar::future<seastar::shared_ptr<AuthResult>> check_impl(const AuthInput &input) = 0;

  private:
    CredentialMechanism mechanism_;
    seastar::metrics::metric_group metrics_;
    size_t total_checks_;
    size_t valid_checks_;
    seastar::timer<seastar::lowres_clock> reset_timer;
  };

  class ShortTermAuthenticator : public Authenticator {
  public:
    static std::vector<char> make_key(const std::vector<char> &password);

    ShortTermAuthenticator() : Authenticator{CredentialMechanism::ShortTerm} {}
  };

  class LongTermAuthenticator : public Authenticator {
  public:
    static constexpr std::chrono::minutes default_nonce_timeout{3};

    static std::vector<char> make_key(
        const seastar::sstring &username,
        const seastar::sstring &realm,
        const std::vector<char> &password,
        PasswordAlgorithm algorithm = PasswordAlgorithm::Md5);

    static std::array<char, 32> make_userhash(const seastar::sstring &username, const seastar::sstring &realm);

    static std::optional<SecurityFeatureSet> parse_feature_set(const seastar::sstring &nonce);

    LongTermAuthenticator(
        std::vector<char> key,
        seastar::sstring realm,
        SecurityFeatureSet feature_set,
        std::chrono::minutes nonce_timeout = default_nonce_timeout,
        bool ignore_nonce_validation = false);

    const seastar::sstring &realm_str() const { return realm_str_; }

    seastar::shared_ptr<RealmAttribute> realm() const { return realm_; }

    SecurityFeatureSet feature_set() const { return feature_set_; }

    seastar::shared_ptr<PasswordAlgorithmsAttribute> algorithms() const { return algorithms_; }

    std::chrono::minutes nonce_timeout() const { return nonce_timeout_; }

  protected:
    // The server MUST NOT choose the same NONCE for two requests unless they have the same source IP address and port.
    seastar::shared_ptr<NonceAttribute> make_nonce(const seastar::socket_address &address) const;

    bool ignore_nonce_validation() const { return ignore_nonce_validation_; }

    std::optional<time_t> parse_time(const seastar::sstring &nonce) const;

  private:
    std::vector<char> key_;
    seastar::sstring realm_str_;
    seastar::shared_ptr<RealmAttribute> realm_;
    SecurityFeatureSet feature_set_;
    seastar::shared_ptr<PasswordAlgorithmsAttribute> algorithms_;
    seastar::sstring prefix_nonce_;
    std::chrono::minutes nonce_timeout_;
    bool ignore_nonce_validation_; // used for testing
  };

  class StaticShortTermAuthenticator final : public ShortTermAuthenticator {
  public:
    StaticShortTermAuthenticator(std::map<seastar::sstring, std::vector<char>> users) : users_{std::move(users)} {
      BOOST_ASSERT(!users_.empty());
    }

    seastar::future<seastar::shared_ptr<AuthResult>> check_impl(const AuthInput &input) override;

  private:
    std::map<seastar::sstring, std::vector<char>> users_;
  };

  class StaticLongTermAuthenticator final : public LongTermAuthenticator {
  public:
    StaticLongTermAuthenticator(
        std::map<seastar::sstring, std::vector<char>> users,
        std::vector<char> key, seastar::sstring realm,
        SecurityFeatureSet feature_set,
        std::chrono::minutes nonce_timeout = default_nonce_timeout,
        bool ignore_nonce_validation = false);

    seastar::future<seastar::shared_ptr<AuthResult>> check_impl(const AuthInput &input) override;

  private:
    std::map<seastar::sstring, std::vector<char>> users_;
    std::map<std::array<char, 32>, seastar::sstring> userhashes_;
  };
}
