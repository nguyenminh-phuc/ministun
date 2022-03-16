#pragma once

#include <seastar/core/shared_ptr.hh>

namespace ms {
  template<class T>
  class ShardedInstance final {
  public:
    seastar::shared_ptr<T> &instance() { return instance_; }

    void construct(seastar::shared_ptr<T> instance) {
      instance_ = instance;
    }

    seastar::future<> stop() {
      if (instance_) return instance_->stop();
      return seastar::make_ready_future<>();
    }

  private:
    seastar::shared_ptr<T> instance_;
  };
}
