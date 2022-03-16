#include <ministun/Authenticator.h>
#include <algorithm>
#include <openssl/hmac.h>
#include <openssl/md5.h> // https://www.openssl.org/docs/man1.1.1/man3/MD5.html
#include <openssl/sha.h> // https://www.openssl.org/docs/man1.1.1/man3/SHA256.html
#include <boost/beast/core/detail/base64.hpp>
#include <seastar/core/print.hh>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  static const char *read_nonce(const sstring &nonce, size_t &pos, size_t size) {
    if (pos + size - 1 >= nonce.size()) return nullptr;
    const auto value_pos = pos;
    pos += size;
    return nonce.data() + value_pos;
  };

  static const char *read_nonce_till_separator(const sstring &nonce, size_t &pos) {
    const auto value_pos = pos;
    while (true) {
      if (pos >= nonce.size()) return nullptr;
      ++pos;
      if (nonce[pos] == '_') break;
    }
    return nonce.data() + value_pos;
  }

  static std::optional<SecurityFeatureSet> parse_feature_set(const sstring &nonce, size_t &pos) {
    MS_GET(magic, read_nonce(nonce, pos, nonce_cookie.size()), std::nullopt)
    if (!std::equal(magic, magic + nonce_cookie.size(), nonce_cookie.data())) return {};

    static_assert(boost::beast::detail::base64::decoded_size(encoded_feature_set_length) == feature_set_length);
    MS_GET(encoded_raw_set, read_nonce(nonce, pos, encoded_feature_set_length), std::nullopt)
    std::array<unsigned char, feature_set_length> raw_set{};
    boost::beast::detail::base64::decode(raw_set.data(), encoded_raw_set, encoded_feature_set_length);

    SecurityFeatureSet set{};
    if (raw_set[0] & 0b1000'0000) set.password_algorithms = true;
    if (raw_set[0] & 0b100'0000) set.username_anonymity = true;

    return set;
  }

  Authenticator::Authenticator(CredentialMechanism mechanism) :
      mechanism_{mechanism}, total_checks_{}, valid_checks_{} {
    metrics_.add_group("authenticator", {
        metrics::make_derive("total_checks", [this] { return total_checks_; },
                             metrics::description{"Total checks per day"}),
        metrics::make_derive("valid_checks", [this] { return valid_checks_; },
                             metrics::description{"Total valid checks per day"}),
    });

    reset_timer.set_callback([this] {
      total_checks_ = 0;
      valid_checks_ = 0;
    });
    reset_timer.arm_periodic(std::chrono::days{1});
  }

  future<shared_ptr<AuthResult>> Authenticator::check(const AuthInput &input) {
    ++total_checks_;

    return check_impl(input).then([this](shared_ptr<AuthResult> result) {
      BOOST_ASSERT(result);
      if (result->type() == AuthResult::Type::Success) ++valid_checks_;
      return result;
    });
  }

  /* If the MESSAGE-INTEGRITY-SHA256 attribute is present, compute the value for the message integrity as described in
   * Section 14.6, using the password associated with the username. If the MESSAGE-INTEGRITY-SHA256 attribute is not
   * present, then use the same password to compute the value for the message integrity as described in Section 14.5.
   * If the resulting value does not match the contents of the corresponding attribute (MESSAGE-INTEGRITY-SHA256 or
   * MESSAGE-INTEGRITY):
   * - The server MUST reject the request with an error message. This message MUST use an error code of 401
   *   (Unauthenticated).
   * */
  bool Authenticator::validate_integrity(
      const AuthInput &input, const std::vector<char> &key,
      IntegrityAlgorithm &algorithm) {
    if (auto integrity_sha256 = input.request.find<MessageIntegritySha256Attribute>()) {
      algorithm = IntegrityAlgorithm::Sha256;
      return integrity_sha256->validate(input.request_reader, key);
    } else if (auto integrity = input.request.find<MessageIntegrityAttribute>()) {
      algorithm = IntegrityAlgorithm::Sha1;
      return integrity->validate(input.request_reader, key);
    }

    return false;
  }

  std::vector<char> ShortTermAuthenticator::make_key(const std::vector<char> &password) {
    BOOST_ASSERT(!password.empty());
    return password;
  }

  StaticLongTermAuthenticator::StaticLongTermAuthenticator(
      std::map<sstring, std::vector<char>> users,
      std::vector<char> key, sstring realm,
      SecurityFeatureSet feature_set,
      std::chrono::minutes nonce_timeout,
      bool ignore_nonce_validation) :
      LongTermAuthenticator{std::move(key), std::move(realm), feature_set, nonce_timeout, ignore_nonce_validation},
      users_{std::move(users)} {
    BOOST_ASSERT(!users_.empty());

    if (feature_set.username_anonymity) {
      for (const auto &user: users_)
        userhashes_.insert(std::make_pair(make_userhash(user.first, realm_str()), user.first));
    }
  }

  std::vector<char> LongTermAuthenticator::make_key(
      const sstring &username,
      const sstring &realm,
      const std::vector<char> &password,
      PasswordAlgorithm algorithm) {
    BOOST_ASSERT(!username.empty() && !realm.empty() && !password.empty());

    std::vector<char> input;
    input.reserve(username.size() + 1 + realm.size() + 1 + password.size());
    input.insert(input.cend(), username.cbegin(), username.cend());
    input.push_back(':');
    input.insert(input.cend(), realm.cbegin(), realm.cend());
    input.push_back(':');
    input.insert(input.cend(), password.cbegin(), password.cend());

    std::vector<char> hash;
    if (algorithm == PasswordAlgorithm::Md5) {
      hash.resize(MD5_DIGEST_LENGTH);
      BOOST_VERIFY(MD5(
          reinterpret_cast<const unsigned char *>(input.data()), input.size(),
          reinterpret_cast<unsigned char *>(hash.data())));
    } else {
      hash.resize(SHA256_DIGEST_LENGTH);
      BOOST_VERIFY(SHA256(
          reinterpret_cast<const unsigned char *>(input.data()), input.size(),
          reinterpret_cast<unsigned char *>(hash.data())));
    }

    return hash;
  }

  std::array<char, 32> LongTermAuthenticator::make_userhash(const sstring &username, const sstring &realm) {
    BOOST_ASSERT(!username.empty() && !realm.empty());

    std::vector<char> input;
    input.reserve(username.size() + 1 + realm.size());
    input.insert(input.cend(), username.cbegin(), username.cend());
    input.push_back(':');
    input.insert(input.cend(), realm.cbegin(), realm.cend());

    std::array<char, 32> hash{};
    BOOST_VERIFY(SHA256(
        reinterpret_cast<const unsigned char *>(input.data()), input.size(),
        reinterpret_cast<unsigned char *>(hash.data())));

    return hash;
  }

  std::optional<SecurityFeatureSet> LongTermAuthenticator::parse_feature_set(const sstring &nonce) {
    size_t pos{};
    return ms::parse_feature_set(nonce, pos);
  }

  LongTermAuthenticator::LongTermAuthenticator(
      std::vector<char> key,
      sstring realm,
      SecurityFeatureSet feature_set,
      std::chrono::minutes nonce_timeout,
      bool ignore_nonce_validation) :
      Authenticator{CredentialMechanism::LongTerm},
      key_{std::move(key)}, realm_str_{std::move(realm)}, feature_set_{feature_set},
      nonce_timeout_{nonce_timeout}, ignore_nonce_validation_{ignore_nonce_validation} {
    BOOST_ASSERT(!key_.empty() && !realm_str_.empty());

    realm_ = make_shared<RealmAttribute>(realm_str_);

    prefix_nonce_ = sstring{nonce_cookie};

    static_assert(boost::beast::detail::base64::encoded_size(feature_set_length) == encoded_feature_set_length);
    std::array<unsigned char, feature_set_length> raw_set{};
    if (feature_set_.password_algorithms) {
      raw_set[0] |= 0b1000'0000;

      std::vector<std::pair<PasswordAlgorithm, std::vector<char>>> algorithms;
      algorithms.emplace_back(PasswordAlgorithm::Sha256, std::vector<char>{});
      algorithms.emplace_back(PasswordAlgorithm::Md5, std::vector<char>{});
      algorithms_ = ::make_shared<PasswordAlgorithmsAttribute>(std::move(algorithms));
    }
    if (feature_set_.username_anonymity) raw_set[0] |= 0b100'0000;

    std::array<char, encoded_feature_set_length> encoded_raw_set{};
    boost::beast::detail::base64::encode(encoded_raw_set.data(), raw_set.data(), feature_set_length);
    prefix_nonce_ += sstring{encoded_raw_set.cbegin(), encoded_raw_set.cend()};
  }

  shared_ptr<NonceAttribute> LongTermAuthenticator::make_nonce(const socket_address &address) const {
    sstring nonce = prefix_nonce_;

    const auto time_t = lowres_system_clock::to_time_t(lowres_system_clock::now());
    const auto time_address_str = format("{}_{}_", time_t, address);
    nonce += time_address_str;

    std::array<char, 20> hash{};
    unsigned length;
    BOOST_VERIFY(HMAC(
        EVP_sha1(),
        key_.data(), static_cast<int>(key_.size()),
        reinterpret_cast<const unsigned char *>(nonce.data()), nonce.size(),
        reinterpret_cast<unsigned char *>(hash.data()), &length));
    BOOST_ASSERT(length == 20);

    const auto hash_str = Utils::sha1_to_string(hash);
    nonce += hash_str;

    BOOST_ASSERT(nonce.size() <= max_nonce_length);

    return make_shared<NonceAttribute>(std::move(nonce));
  }

  std::optional<time_t> LongTermAuthenticator::parse_time(const sstring &nonce) const {
    size_t pos;

    MS_GET(feature_set, ms::parse_feature_set(nonce, pos), std::nullopt)

    MS_GET(time_ptr, read_nonce_till_separator(nonce, pos), std::nullopt)
    MS_GET(time, Utils::time_from_string(sstring{time_ptr, time_ptr + pos}), std::nullopt)

    ++pos;

    MS_GET(address, read_nonce_till_separator(nonce, pos), std::nullopt)

    ++pos;

    MS_GET(hash_ptr, read_nonce(nonce, pos, 20), std::nullopt)
    std::array<char, 20> hash{};
    std::copy_n(hash_ptr, 20, hash.begin());

    if (pos != nonce.size()) return {};

    std::array<char, 20> computed_hash{};
    unsigned length;
    BOOST_VERIFY(HMAC(
        EVP_sha1(),
        key_.data(), static_cast<int>(key_.size()),
        reinterpret_cast<const unsigned char *>(nonce.data()), nonce.size() - 20,
        reinterpret_cast<unsigned char *>(computed_hash.data()), &length));
    BOOST_ASSERT(length == 20);

    if (hash != computed_hash) return {};

    return time;
  }

  /* If the message does not contain
   * 1) a MESSAGE-INTEGRITY or a MESSAGE-INTEGRITY-SHA256 attribute and
   * 2) a USERNAME attribute:
   * - The server MUST reject the request with an error message. This message MUST use an error code of 400
   *   (Bad Request).
   * If the USERNAME does not contain a username value currently valid within the server:
   * - The server MUST reject the request with an error message. This message MUST use an error code of 401
   *   (Unauthenticated).
   * */
  future<shared_ptr<AuthResult>>
  StaticShortTermAuthenticator::check_impl(const AuthInput &input) {
    BOOST_ASSERT(input.request.cls() == Class::Request);

    return futurize_invoke([this, &input]() -> shared_ptr<AuthResult> {
      const auto integrity_sha256 = input.request.find<MessageIntegritySha256Attribute>();
      const auto integrity = input.request.find<MessageIntegrityAttribute>();
      const auto username = input.request.find<UsernameAttribute>();

      if ((!integrity_sha256 && !integrity) || !username)
        return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());

      const auto it = users_.find(username->string());
      if (it == users_.cend())
        return make_shared<ErrorAuthResult>(ErrorCodeAttribute::Unauthenticated());

      IntegrityAlgorithm algorithm;
      auto key = make_key(it->second);
      if (!validate_integrity(input, key, algorithm))
        return make_shared<ErrorAuthResult>(ErrorCodeAttribute::Unauthenticated());

      return ::make_shared<SuccessAuthResult>(algorithm, std::move(key));
    });
  }

  future<shared_ptr<AuthResult>>
  StaticLongTermAuthenticator::check_impl(const AuthInput &input) {
    BOOST_ASSERT(input.request.cls() == Class::Request);

    return futurize_invoke([this, &input]() -> shared_ptr<AuthResult> {
      /* If the message does not contain a MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, the server MUST
       * generate an error message with an error code of 401 (Unauthenticated). This message MUST include a REALM
       * value. The message MUST include a NONCE, selected by the server. The server MUST NOT choose the same NONCE for
       * two requests unless they have the same source IP address and port. The server MAY support alternate password
       * algorithms, in which case it can list them in preferential order in a PASSWORD-ALGORITHMS attribute. If the
       * server adds a PASSWORD-ALGORITHMS attribute, it MUST set the STUN Security Feature "Password algorithms" bit to
       * 1. The server MAY support anonymous username, in which case it MUST set the STUN Security Feature "Username
       * anonymity" bit set to 1. The message SHOULD NOT contain a USERNAME, USERHASH, MESSAGE-INTEGRITY, or
       * MESSAGE-INTEGRITY-SHA256 attribute.
       * */
      const auto integrity_sha256 = input.request.find<MessageIntegritySha256Attribute>();
      const auto integrity = input.request.find<MessageIntegrityAttribute>();
      if ((!integrity_sha256 && !integrity)) {
        std::vector<shared_ptr<Attribute>> attributes = {
            ErrorCodeAttribute::Unauthenticated(),
            realm(),
            make_nonce(input.remote_address),
            algorithms()
        };
        return ::make_shared<ErrorAuthResult>(std::move(attributes));
      }

      /* If the message contains a MESSAGE-INTEGRITY or a MESSAGE-INTEGRITY-SHA256 attribute, but is missing either the
       * USERNAME or USERHASH, REALM, or NONCE attribute, the server MUST generate an error message with an error code
       * of 400 (Bad Request). This message SHOULD NOT include a USERNAME, USERHASH, NONCE, or REALM attribute. The
       * message cannot contain a MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, as the attributes required
       * to generate them are missing.
       * */
      const auto username = input.request.find<UsernameAttribute>();
      const auto userhash = input.request.find<UserhashAttribute>();
      const auto realm = input.request.find<RealmAttribute>();
      auto nonce = input.request.find<NonceAttribute>();
      if (((username && userhash) || (!username && !userhash)) || !realm || !nonce)
        return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());

      if (realm->string() != this->realm()->string())
        return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());

      std::optional<time_t> nonce_time_t;
      if (!ignore_nonce_validation()) {
        nonce_time_t = parse_time(nonce->string());
        if (!nonce_time_t) return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());
      }

      /* If the NONCE attribute starts with the "nonce cookie" with the STUN Security Feature "Password algorithms" bit
       * set to 1, the server performs these checks in the order specified:
       * - If the request contains neither the PASSWORD-ALGORITHMS nor the PASSWORD-ALGORITHM algorithm, then the
       *   request is processed as though PASSWORD-ALGORITHM were MD5.
       * - Otherwise, unless
       *   (1) PASSWORD-ALGORITHM and PASSWORD-ALGORITHMS are both present,
       *   (2) PASSWORD-ALGORITHMS matches the value sent in the message that sent this NONCE, and
       *   (3) PASSWORD-ALGORITHM matches one of the entries in PASSWORD-ALGORITHMS,
       *   the server MUST generate an error message with an error code of 400 (Bad Request).
       * */
      PasswordAlgorithm password_algorithm;
      if (feature_set().password_algorithms) {
        const auto algorithms = input.request.find<PasswordAlgorithmsAttribute>();
        const auto algorithm = input.request.find<PasswordAlgorithmAttribute>();
        if (!algorithms && !algorithm) password_algorithm = PasswordAlgorithm::Md5;
        else {
//          PASSWORD-ALGORITHMS can be absent: https://www.rfc-editor.org/errata/rfc8489
//          if (!algorithms || !algorithm) return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());

          if (algorithms) {
            if (algorithms->algorithms().empty()) return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());
            for (const auto &algo: algorithms->algorithms()) {
              if (algo.first != PasswordAlgorithm::Sha256 && algo.first != PasswordAlgorithm::Md5)
                return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());
            }
          }

          if (algorithm->algorithm() != PasswordAlgorithm::Sha256 && algorithm->algorithm() != PasswordAlgorithm::Md5)
            return make_shared<ErrorAuthResult>(ErrorCodeAttribute::BadRequest());
          password_algorithm = algorithm->algorithm();
        }
      } else password_algorithm = PasswordAlgorithm::Md5;

      /* If the value of the USERNAME or USERHASH attribute is not valid, the server MUST generate an error message
       * with an error code of 401 (Unauthenticated). This message MUST include a REALM value. The message MUST
       * include a NONCE, selected by the server. The message MUST include a PASSWORD-ALGORITHMS attribute. The
       * message SHOULD NOT contain a USERNAME or USERHASH attribute. The message MAY include a MESSAGE-INTEGRITY or
       * MESSAGE-INTEGRITY-SHA256 attribute, using the previous key to calculate it.
       * */
      auto user_it = users_.cend();
      if (userhash) {
        const auto hash_it = userhashes_.find(userhash->string());
        if (hash_it != userhashes_.cend()) user_it = users_.find(hash_it->second);
      } else user_it = users_.find(username->string());
      if (user_it == users_.cend()) {
        std::vector<shared_ptr<Attribute>> attributes = {
            ErrorCodeAttribute::Unauthenticated(),
            this->realm(),
            make_nonce(input.remote_address),
            algorithms()
        };
        return ::make_shared<ErrorAuthResult>(std::move(attributes));
      }

      /* If the resulting value does not match the contents of the MESSAGE-INTEGRITY attribute or the
       * MESSAGE-INTEGRITY-SHA256 attribute, the server MUST reject the request with an error message. This message
       * MUST use an error code of 401 (Unauthenticated). It MUST include the REALM and NONCE attributes and SHOULD NOT
       * include the USERNAME, USERHASH, MESSAGE-INTEGRITY, or MESSAGE-INTEGRITY-SHA256 attribute.
       * */
      IntegrityAlgorithm integrity_algorithm;
      auto key = make_key(user_it->first, realm_str(), user_it->second, password_algorithm);
      if (!validate_integrity(input, key, integrity_algorithm)) {
        std::vector<shared_ptr<Attribute>> attributes = {
            ErrorCodeAttribute::Unauthenticated(),
            this->realm(),
            std::move(nonce),
            algorithms()
        };
        return ::make_shared<ErrorAuthResult>(std::move(attributes));
      }

      if (!ignore_nonce_validation()) {
        /* If the NONCE is no longer valid, the server MUST generate an error message with an error code of 438 (Stale
         * Nonce). This message MUST include NONCE, REALM, and PASSWORD-ALGORITHMS attributes and SHOULD NOT include the
         * USERNAME and USERHASH attributes. The NONCE attribute value MUST be valid. The message MAY include a
         * MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, using the previous NONCE to calculate it.
         * */
        const auto nonce_time = lowres_system_clock::from_time_t(*nonce_time_t);
        const auto current_time = lowres_system_clock::now();
        if (current_time - nonce_time > nonce_timeout()) {
          std::vector<shared_ptr<Attribute>> attributes = {
              ErrorCodeAttribute::StaleNonce(),
              make_nonce(input.remote_address),
              this->realm(),
              algorithms()
          };
          return ::make_shared<ErrorAuthResult>(std::move(attributes));
        }
      }

      /* If these checks pass, the server continues to process the request. Any message generated by the server MUST
       * include the MESSAGE-INTEGRITY-SHA256 attribute, computed using the username and password utilized to
       * authenticate the request, unless the request was processed as though PASSWORD-ALGORITHM was MD5 (because the
       * request contained neither PASSWORD-ALGORITHMS nor PASSWORD-ALGORITHM). In that case, the MESSAGE-INTEGRITY
       * attribute MUST be used instead of the MESSAGE-INTEGRITY-SHA256 attribute, and the REALM, NONCE, USERNAME, and
       * USERHASH attributes SHOULD NOT be included.
       * */
      return ::make_shared<SuccessAuthResult>(integrity_algorithm, std::move(key));
    });
  }
}
