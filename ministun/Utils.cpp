#include <ministun/Utils.h>
#include <ctype.h>
#include <algorithm>
#include <random>
#include <sstream>
#include <string>

using namespace seastar;

namespace ms {
  std::istream &operator>>(std::istream &in, Family &family) {
    sstring token;
    in >> token;
    if (!in) return in;

    if (auto value = family_from_string(token)) family = *value;
    else in.setstate(std::ios_base::failbit);

    return in;
  }

  std::ostream &operator<<(std::ostream &os, Family family) {
    if (family == Family::Inet) os << "4";
    else os << "6";

    return os;
  }

  std::istream &operator>>(std::istream &in, Protocol &protocol) {
    sstring token;
    in >> token;
    if (!in) return in;

    if (auto value = protocol_from_string(Utils::to_lower(token))) protocol = *value;
    else in.setstate(std::ios_base::failbit);

    return in;
  }

  std::ostream &operator<<(std::ostream &os, Protocol protocol) {
    os << protocol_strs[Utils::to_underlying(protocol)];

    return os;
  }

  std::istream &operator>>(std::istream &in, CredentialMechanism &mechanism) {
    sstring token;
    in >> token;
    if (!in) return in;

    token = Utils::to_lower(token);
    if (token == "shorterm") mechanism = CredentialMechanism::ShortTerm;
    else if (token == "longterm") mechanism = CredentialMechanism::LongTerm;
    else in.setstate(std::ios_base::failbit);

    return in;
  }

  std::ostream &operator<<(std::ostream &os, CredentialMechanism mechanism) {
    if (mechanism == CredentialMechanism::ShortTerm) os << "ShortTerm";
    else os << "LongTerm";

    return os;
  }

  char Utils::random() {
    thread_local std::random_device dev;
    thread_local std::mt19937 rng{dev()};
    thread_local std::uniform_int_distribution<char> dist;

    return dist(rng);
  }

  std::optional<uint16_t> Utils::u16_from_string(const sstring &string) {
    try {
      const auto value = std::stoi(string);
      if (value <= static_cast<int>(UINT16_MAX) && value >= 0) return static_cast<uint16_t>(value);
      return {};
    } catch (const std::invalid_argument &e) {
      MS_TRACE("Invalid u16 {}. Exception invalid_argument caught: {}", string, e.what());
      return {};
    } catch (const std::out_of_range &e) {
      MS_TRACE("Invalid u16 {}. Exception out_of_range caught: {}", string, e.what());
      return {};
    }
  }

  std::optional<time_t> Utils::time_from_string(const sstring &string) {
    static_assert(std::is_integral<time_t>::value);

    try {
      if constexpr (std::is_same<time_t, unsigned long>::value) return std::stoul(string);
      else if constexpr (std::is_same<time_t, unsigned long long>::value) return std::stoull(string);
      else if constexpr (std::is_same<time_t, int>::value) return std::stoi(string);
      else if constexpr (std::is_same<time_t, long>::value) return std::stol(string);
      else return std::stoll(string);
    } catch (const std::invalid_argument &e) {
      MS_TRACE("Invalid time_t {}. Exception invalid_argument caught: {}", string, e.what());
      return {};
    } catch (const std::out_of_range &e) {
      MS_TRACE("Invalid time_t {}. Exception out_of_range caught: {}", string, e.what());
      return {};
    }
  }

  std::optional<net::inet_address> Utils::ip_from_string(const sstring &string) {
    try {
      return net::inet_address(string);
    } catch (const std::invalid_argument &e) {
      MS_TRACE("Invalid address {}. Exception invalid_argument caught: {}", string, e.what());
      return {};
    }
  }

  std::optional<log_level> Utils::log_level_from_string(const sstring &string) {
    std::istringstream ss{Utils::to_lower(string)};
    log_level log_level;
    ss >> log_level;
    if (!ss) return {};

    return log_level;
  }

  sstring Utils::sha1_to_string(const std::array<char, 20> &hash) {
    std::stringstream ss;
    for (char c: hash) ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & static_cast<unsigned int>(c));
    return ss.str();
  }

  sstring Utils::to_lower(const sstring &string) {
    sstring lower_string = string;
    std::transform(lower_string.cbegin(), lower_string.cend(), lower_string.begin(), [](auto c) { return tolower(c); });
    return lower_string;
  }
}
