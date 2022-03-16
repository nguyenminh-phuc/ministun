#include <ministun/RateLimiter.h>
#include <algorithm>
#include <boost/assert.hpp>
#include <seastar/net/ip.hh>

using namespace seastar;

namespace ms {
  TrackedId::TrackedId(const net::inet_address &address) : bytes{} {
    if (address.is_ipv4()) {
      const auto ipv4 = address.as_ipv4_address().ip;
      std::copy_n(&ipv4, 4, bytes.data());
    } else std::copy_n(address.as_ipv6_address().ip.data(), 16, bytes.data());
  }

  RateLimiter::RateLimiter() {
    metrics_.add_group("rate_limiter", {
        metrics::make_derive("permits", [this]() -> size_t { return permits_; },
                             metrics::description{"Total permits per day"}),
        metrics::make_derive("blocks", [this]() -> size_t { return blocks_; },
                             metrics::description{"Total blocks per day"}),
    });

    reset_timer_.set_callback([this] { reset_counters(); });
    reset_timer_.arm_periodic(std::chrono::days{1});
  }

  bool RateLimiter::permit(const net::inet_address &address) {
    const auto permitted = permit_impl(address);
    if (permitted) ++permits_;
    else ++blocks_;

    return permitted;
  }

  bool ModuloRateLimiter::permit_impl(const net::inet_address &address) {
    const auto id = TrackedId{address};
    const auto index = TrackedId::hash()(id) % lock_divisor;

    std::lock_guard<std::mutex> lock(mutexes_[index]);

    const auto current_time = lowres_clock::now();

    auto it = maps_[index].find(id);
    if (it == maps_[index].cend()) {
      if (maps_[index].size() == max_tracked_addresses_) maps_[index].clear();

      maps_[index][TrackedId{address}] = {
          .address = address,
          .permits = rate_ - 1,
          .first_time = current_time,
          .last_time = current_time
      };

      return true;
    }

    if (it->second.blocked) {
      --it->second.permits;
      if (!it->second.permits) {
        it->second.permits = default_rate;
        block_timeout_ += default_blocked_timeout;
      }

      if (it->second.last_time + block_timeout_ >= current_time) return false;

      it->second.permits = rate_ - 1;
      it->second.first_time = it->second.last_time = current_time;
      it->second.blocked = false;
      return true;
    }

    if (current_time - it->second.first_time > std::chrono::minutes{1}) {
      it->second.permits = rate_ - 1;
      it->second.first_time = it->second.last_time = current_time;
      return true;
    }

    it->second.last_time = current_time;
    --it->second.permits;
    if (!it->second.permits) {
      it->second.permits = default_rate;
      it->second.blocked = true;
      return false;
    }

    return true;
  }

  void ModuloRateLimiter::reset_counters() {
    std::array<std::unique_ptr<std::lock_guard<std::mutex>>, lock_divisor> locks;

    for (size_t i = 0; i < lock_divisor; ++i) {
      locks[i] = std::make_unique<std::lock_guard<std::mutex>>(mutexes_[i]);
      maps_[i].clear();
    }

    permits_ = 0;
    blocks_ = 0;
  }
}
