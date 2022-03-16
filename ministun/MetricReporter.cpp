#include <ministun/MetricReporter.h>
#include <exception>
#include <ministun/Utils.h>

using namespace seastar;

namespace ms {
  MetricReporter::MetricReporter(const socket_address &address) : limit_{1}, address_{address} {
    config_.prefix = "ministun";
  }

  future<bool> MetricReporter::start() {
    return with_semaphore(limit_, 1, [this] {
      if (server_) return make_ready_future<bool>(true);

      server_ = std::make_unique<http_server_control>();
      return server_->start("prometheus").then([this] {
        return prometheus::start(*server_, config_);
      }).then([this] {
        listen_options options;
        options.reuse_address = true;
        return server_->listen(address_, options);
      }).then_wrapped([this](future<> f) {
        try {
          f.get();
          MS_INFO("Started Prometheus server");
          return true;
        } catch (const std::exception &e) {
          MS_WARN("Prometheus server failed to start on {}. Exception caught: {}", address_, e.what());
          return false;
        }
      });
    });
  }

  future<> MetricReporter::stop() {
    return with_semaphore(limit_, 1, [this] {
      if (!server_) return make_ready_future<>();
      return server_->stop().then([this] {
        MS_INFO("Stopped Prometheus server");
        server_.reset();
      });
    });
  }
}
