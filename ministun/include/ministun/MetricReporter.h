#pragma once

#include <memory>
#include <utility>
#include <seastar/core/prometheus.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/http/httpd.hh>
#include <seastar/net/socket_defs.hh>

namespace ms {
  class MetricReporter final {
  public:
    MetricReporter(const seastar::socket_address &address);

    seastar::future<bool> start();

    seastar::future<> stop();

  private:
    seastar::semaphore limit_;
    seastar::socket_address address_;
    std::unique_ptr<seastar::http_server_control> server_;
    seastar::prometheus::config config_;
  };
}
