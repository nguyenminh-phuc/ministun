#include <ministun/ClientCred.h>
#include <ministun/Authenticator.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  static bool validate_integrity(
      const MessageBufferReader &response_reader, const Message &response,
      const std::vector<char> &key,
      IntegrityAlgorithm algorithm) {
    const auto integrity_sha256 = response.find<MessageIntegritySha256Attribute>();
    const auto integrity = response.find<MessageIntegrityAttribute>();

    if (!integrity_sha256 && !integrity) {
      MS_WARN("No integrity attribute is present in message");
      return false;
    }

    if (integrity_sha256 && integrity) {
      MS_WARN("Both MESSAGE-INTEGRITY-SHA256 and MESSAGE-INTEGRITY attributes are present in message");
      return false;
    }

    if (algorithm == IntegrityAlgorithm::Sha256) {
      if (!integrity_sha256) {
        MS_WARN("No MESSAGE-INTEGRITY-SHA256 attribute is present in message");
        return false;
      }

      if (!integrity_sha256->validate(response_reader, key)) {
        MS_WARN("Failed to validate MESSAGE-INTEGRITY-SHA256");
        return false;
      }
    } else {
      if (!integrity) {
        MS_WARN("No MESSAGE-INTEGRITY attribute is present in message");
        return false;
      }

      if (!integrity->validate(response_reader, key)) {
        MS_WARN("Failed to validate MESSAGE-INTEGRITY");
        return false;
      }
    }

    return true;
  }

//  static ClientCred::Response check_response(const Message &message) {
//    if (message.cls() == Class::ErrorResponse) {
//      std::stringstream ss;
//
//      if (auto error = message.find<ErrorCodeAttribute>()) {
//        const auto code = static_cast<int>(error->code());
//        sstring reason = "<blank>";
//        if (!error->reason_phrase().empty())
//          reason = sstring{error->reason_phrase().cbegin(), error->reason_phrase().cend()};
//        ss << "Error code " << code << ", reason phrase: " << reason << ". ";
//
//        if (code >= 300 && code <= 399) {
//          if (auto server = message.find<AlternateServerAttribute>())
//            ss << "Alternate server: " << server->address();
//        } else if (code >= 400 && code <= 499) {
//          if (static_cast<ErrorCode>(code) == ErrorCode::UnknownAttribute) {
//            if (auto unknown = message.find<UnknownAttributesAttribute>()) {
//              std::stringstream ss2;
//              for (size_t i = 0; i < unknown->types().size(); ++i) {
//                if (i == 0) ss2 << static_cast<int>(unknown->types()[i]);
//                else ss2 << ", " << static_cast<int>(unknown->types()[i]);
//              }
//              ss << "Unknown attributes: " << ss2.str();
//            }
//          }
//        }
//      }
//
//      MS_WARN("Received error message. {}", ss.str());
//      return ClientCred::Response::Error;
//    }
//
//    return ClientCred::Response::Success;
//  }

  ShortTermClientCred::ShortTermClientCred(sstring username, const std::vector<char> &password) :
      ClientCred{CredentialMechanism::ShortTerm},
      username_{std::move(username)}, key_{ShortTermAuthenticator::make_key(password)} {
    BOOST_ASSERT(!username_.empty() && !key_.empty());
  }

  ShortTermClientCred::ShortTermClientCred(
      sstring username, const std::vector<char> &password,
      IntegrityAlgorithm algorithm) :
      ShortTermClientCred{std::move(username), password} {
    algorithm_ = algorithm;
  }

  /* The agent MUST include the USERNAME, MESSAGE-INTEGRITY-SHA256, and MESSAGE-INTEGRITY attributes in the message
   * unless the agent knows from an external mechanism which message integrity algorithm is supported by both agents.
   * In this case, either MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 MUST be included in addition to USERNAME.
   *
   * A client sending subsequent requests to the same server MUST send only the MESSAGE-INTEGRITY-SHA256 or the
   * MESSAGE-INTEGRITY attribute that matches the attribute that was received in the message to the initial request.
   * */
  void ShortTermClientCred::apply_auth(MessageBufferWriter &request_writer, Message &request) const {
    BOOST_ASSERT(request.cls() == Class::Request);

    request.add(make_shared<UsernameAttribute>(username_));

    if (!algorithm_) {
      request.add(MessageIntegrityAttribute::dummy());
      request.add(MessageIntegritySha256Attribute::dummy());
    } else if (*algorithm_ == IntegrityAlgorithm::Sha256)
      request.add(MessageIntegritySha256Attribute::dummy());
    else request.add(MessageIntegrityAttribute::dummy());

    request_writer.set_key(key_);
  }

  ClientCred::Result ShortTermClientCred::validate_auth(const MessageBufferReader &response_reader, Message &response) {
    BOOST_ASSERT(response.cls() == Class::SuccessResponse || response.cls() == Class::ErrorResponse);

    if (response.find<MessageIntegritySha256Attribute>()) algorithm_ = IntegrityAlgorithm::Sha256;
    else algorithm_ = IntegrityAlgorithm::Sha1;

    return validate_integrity(response_reader, response, key_, *algorithm_) ? Result::Success : Result::Error;
  }

  /* If the message contains a PASSWORD-ALGORITHMS attribute, all the subsequent requests MUST be authenticated using
   * MESSAGE-INTEGRITY-SHA256 only.
   * */
  void LongTermClientCred::apply_auth(MessageBufferWriter &request_writer, Message &request) const {
    BOOST_ASSERT(request.cls() == Class::Request);

    if (!cache_) return;

    bool username_added{};
    auto algorithm{IntegrityAlgorithm::Sha1};

    if (cache_->feature_set) {
      if (cache_->feature_set->password_algorithms) {
        BOOST_ASSERT(cache_->algorithms && cache_->algorithm);
        request.add(cache_->algorithms);
        request.add(cache_->algorithm);
        algorithm = IntegrityAlgorithm::Sha256;
      }

      if (cache_->feature_set->username_anonymity) {
        request.add(make_shared<UserhashAttribute>(username_, cache_->realm));
        username_added = true;
      }
    }

    request.add(make_shared<RealmAttribute>(cache_->realm));
    request.add(make_shared<NonceAttribute>(cache_->nonce));

    if (!username_added) request.add(make_shared<UsernameAttribute>(username_));

    if (algorithm == IntegrityAlgorithm::Sha256) request.add(MessageIntegritySha256Attribute::dummy());
    else request.add(MessageIntegrityAttribute::dummy());

    request_writer.set_key(cache_->key);
  }

  ClientCred::Result LongTermClientCred::validate_auth(const MessageBufferReader &response_reader, Message &response) {
    BOOST_ASSERT(response.cls() == Class::SuccessResponse || response.cls() == Class::ErrorResponse);

    const auto error_in_last_response = error_in_last_response_;
    error_in_last_response_ = false;

    auto nonce = response.find<NonceAttribute>();
    auto algorithms = response.find<PasswordAlgorithmsAttribute>();

    /* If the message is an error message with an error code of 401 (Unauthenticated) or 438 (Stale Nonce), the client
     * MUST test if the NONCE attribute value starts with the "nonce cookie". If so and the "nonce cookie" has the STUN
     * Security Feature "Password algorithms" bit set to 1 but no PASSWORD-ALGORITHMS attribute is present, then the
     * client MUST NOT retry the request with a new transaction.
     *
     * For all other responses, if the NONCE attribute starts with the "nonce cookie" with the STUN Security Feature
     * "Password algorithms" bit set to 1 but PASSWORD-ALGORITHMS is not present, the message MUST be ignored.
     * */
    if (nonce && nonce->feature_set() && nonce->feature_set()->password_algorithms && !algorithms) {
      MS_WARN("No PASSWORD-ALGORITHMS attribute is present in message");
      return Result::Error;
    }

    if (response.cls() == Class::ErrorResponse) {
      MS_GET(error, response.find<ErrorCodeAttribute>(), Result::Error)
      if (error->code() == ErrorCode::Unauthenticated || error->code() == ErrorCode::StaleNonce) {
        if (error_in_last_response) return Result::Error;

        if (!nonce) {
          MS_WARN("No NONCE attribute is present in Unauthenticated/Stale Nonce message");
          return Result::Error;
        }

        /* If the message is an error message with an error code of 401 (Unauthenticated), the client SHOULD retry the
         * request with a new transaction. This request MUST contain a USERNAME or a USERHASH, determined by the client
         * as the appropriate username for the REALM from the error message. If the "nonce cookie" is present and has
         * the STUN Security Feature "Username anonymity" bit set to 1, then the  USERHASH attribute MUST be used; else,
         * the USERNAME attribute MUST be used. The request MUST contain the REALM, copied from the error message. The
         * request MUST contain the NONCE, copied from the error message. If the message contains a
         * PASSWORD-ALGORITHMS attribute, the request MUST contain the PASSWORD-ALGORITHMS attribute with the same
         * content. If the message contains a PASSWORD-ALGORITHMS attribute, and this attribute contains at least one
         * algorithm that is supported by the client, then the request MUST contain a PASSWORD-ALGORITHM attribute with
         * the first algorithm supported on the list. If the message contains a PASSWORD-ALGORITHMS attribute, and
         * this attribute does not contain any algorithm that is supported by the client, then the client MUST NOT retry
         * the request with a new transaction. The client MUST NOT perform this retry if it is not changing the
         * USERNAME, USERHASH, REALM, or its associated password from the previous attempt.
         * */
        if (error->code() == ErrorCode::Unauthenticated) {
          MS_GET(realm, response.find<RealmAttribute>(), Result::Error)

          std::vector<char> key;
          shared_ptr<PasswordAlgorithmAttribute> algorithm;
          if (nonce->feature_set() && nonce->feature_set()->password_algorithms) {
            for (const auto &algo: algorithms->algorithms()) {
              if (algo.first == PasswordAlgorithm::Sha256 || algo.first == PasswordAlgorithm::Md5) {
                algorithm = ::make_shared<PasswordAlgorithmAttribute>(algo.first, std::vector<char>{});
                break;
              }
            }

            if (!algorithm) {
              MS_WARN("No supported password is present in Unauthenticated message");
              return Result::Error;
            }

            key = LongTermAuthenticator::make_key(username_, realm->string(), password_, algorithm->algorithm());
          } else key = LongTermAuthenticator::make_key(username_, realm->string(), password_);

          error_in_last_response_ = true;
          cache_ = std::make_optional(LongTermClientCred::Cache{
              .realm = realm->string(),
              .nonce = nonce->string(),
              .key = std::move(key),
              .feature_set = nonce->feature_set(),
              .algorithms = std::move(algorithms),
              .algorithm = std::move(algorithm)
          });
        } else {
          if (!cache_) {
            MS_WARN("The cache should have existed");
            return Result::Error;
          }

          auto algorithm{IntegrityAlgorithm::Sha1};
          if (cache_->feature_set && cache_->feature_set->password_algorithms) algorithm = IntegrityAlgorithm::Sha256;
          if (!validate_integrity(response_reader, response, cache_->key, algorithm))
            return Result::Error;

          /* If the message is an error message with an error code of 438 (Stale Nonce), the client MUST retry the
           * request, using the new NONCE attribute supplied in the 438 (Stale Nonce) message. This retry MUST also
           * include either the USERNAME or USERHASH, the REALM, and either the MESSAGE-INTEGRITY or
           * MESSAGE-INTEGRITY-SHA256 attribute.
           * */
          cache_->nonce = nonce->string();
          error_in_last_response_ = true;
        }

        return Result::Retry;
      }

        /* If the message is an error message with an error code of 400 (Bad Request) and does not contain either the
         * MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, then the message MUST be discarded, as if it were
         * never received. This means that retransmits, if applicable, will continue.
         * */
      else if (error->code() == ErrorCode::BadRequest) {
        if (!response.find<MessageIntegritySha256Attribute>() && !response.find<MessageIntegrityAttribute>())
        MS_WARN("No integrity attribute is present in Bad Request message");
        return Result::Error;
      }
    }

    /* The client looks for the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute in the message (either success
     * or failure). If present, the client computes the message integrity over the message as defined in Sections 14.5
     * or 14.6, using the same password it utilized for the request. If the resulting value matches the contents of the
     * MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, the message is considered authenticated. If the value
     * does not match, or if both MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256 are absent, the processing depends on
     * the request being sent over a reliable or an unreliable transport.
     *
     * If the request was sent over an unreliable transport, the message MUST be discarded, as if it had never been
     * received. This means that retransmits, if applicable, will continue. If all the responses received are discarded,
     * then instead of signaling a timeout after ending the transaction, the layer MUST signal that the integrity
     * protection was violated.
     * */
    if (cache_) {
      auto algorithm{IntegrityAlgorithm::Sha1};
      if (cache_->feature_set && cache_->feature_set->password_algorithms) algorithm = IntegrityAlgorithm::Sha256;
      if (!validate_integrity(response_reader, response, cache_->key, algorithm)) return Result::Error;
    }

    return Result::Success;
  }
}
