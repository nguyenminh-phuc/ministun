#include <ministun/Uri.h>
#include <uriparser/Uri.h>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  static std::optional<sstring> parse_value(const UriTextRangeStructA &value) {
    if (value.first && value.afterLast && value.first != value.afterLast) return sstring{value.first, value.afterLast};
    return {};
  }

  class Parser final {
  public:
    Parser(const sstring &uri_str) : uri_{} {
      if (auto rc = uriParseSingleUriA(&uri_, uri_str.data(), nullptr) != URI_SUCCESS) {
        MS_DEBUG("Failed to parse URI {}, uriparser returned {}", uri_str, rc);
        return;
      }

      parsed_ = true;
    }

    std::optional<Uri> parse() const {
      if (!parsed_) return {};
      Uri uri;

      MS_GET(scheme, parse_value(uri_.scheme), std::nullopt)
      const auto lower_scheme = Utils::to_lower(*scheme);

      MS_GET(service, service_from_string(lower_scheme), std::nullopt)
      uri.service = *service;

      MS_GET(host_str, parse_value(uri_.hostText), std::nullopt)
      auto lower_host_str = Utils::to_lower(*host_str);

      if (auto ip = Utils::ip_from_string(lower_host_str)) uri.host = *ip;
      else uri.host = lower_host_str;

      if (auto port_str = parse_value(uri_.portText)) {
        MS_GET(numeric_port, Utils::u16_from_string(*port_str), std::nullopt)
        uri.port = *numeric_port;
      } else uri.port = service_default_ports[Utils::to_underlying(uri.service)];

      return uri;
    }

    ~Parser() {
      if (parsed_) uriFreeUriMembersA(&uri_);
    }

  private:
    UriUriA uri_;
    bool parsed_;
  };

  std::optional<Uri> Uri::parse(const sstring &uri_str) {
    Parser parser{uri_str};
    return parser.parse();
  }
}
