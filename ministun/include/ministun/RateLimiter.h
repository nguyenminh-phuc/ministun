#pragma once

#include <stddef.h>
#include <stdint.h>
#include <atomic>
#include <array>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <seastar/core/lowres_clock.hh>
#include <seastar/core/metrics.hh>
#include <seastar/core/timer.hh>
#include <seastar/net/inet_address.hh>

namespace ms {
  struct TrackedId {
    TrackedId(const seastar::net::inet_address &address);

    std::array<uint64_t, 2> bytes;

    struct hash {
      size_t operator()(const TrackedId &id) const {
        return id.bytes[0] ^ id.bytes[1];
      }
    };

    struct equal {
      bool operator()(const TrackedId &a, const TrackedId &b) const {
        return a.bytes == b.bytes;
      }
    };
  };

  struct TrackedAddress {
    seastar::net::inet_address address;
    size_t permits;
    seastar::lowres_clock::time_point first_time;
    seastar::lowres_clock::time_point last_time;
    bool blocked;
  };

  class RateLimiter {
  public:
    RateLimiter();

    virtual ~RateLimiter() = default;

    bool permit(const seastar::net::inet_address &address);

  protected:
    std::atomic<size_t> permits_;
    std::atomic<size_t> blocks_;

    virtual bool permit_impl(const seastar::net::inet_address &address) = 0;

    virtual void reset_counters() {
      permits_ = 0;
      blocks_ = 0;
    }

  private:
    seastar::metrics::metric_group metrics_;
    seastar::timer<seastar::lowres_clock> reset_timer_;
  };

  // Although there can be better ways to limit rate, the division hashing method is the simplest
  class ModuloRateLimiter final : public RateLimiter {
  public:
    // A divisor should be a prime number to make sure the keys are distributed with more uniformity
    static constexpr size_t lock_divisor = 5;
    static constexpr size_t default_rate = 30;
    static constexpr std::chrono::minutes default_blocked_timeout{15};
    static constexpr size_t default_max_tracked_addresses = 20000;

    ModuloRateLimiter(
        size_t rate = default_rate, // rate == permits per minute
        std::chrono::minutes block_timeout = default_blocked_timeout,
        size_t max_tracked_addresses = default_max_tracked_addresses) :
        rate_{rate}, block_timeout_{block_timeout}, max_tracked_addresses_{max_tracked_addresses} {
      BOOST_ASSERT(rate && block_timeout.count() && max_tracked_addresses);
    }

    bool permit_impl(const seastar::net::inet_address &address) override;

    void reset_counters() override;

  private:
    std::array<std::mutex, lock_divisor> mutexes_;
    size_t rate_;
    std::chrono::minutes block_timeout_;
    size_t max_tracked_addresses_;
    std::array<std::unordered_map<TrackedId, TrackedAddress, TrackedId::hash, TrackedId::equal>, lock_divisor> maps_;
  };
}
