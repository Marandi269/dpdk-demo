#ifndef __BLOCKING_QUEUE_HPP__
#define __BLOCKING_QUEUE_HPP__
#include <condition_variable>
#include <mutex>
#include <queue>
using std::condition_variable;
using std::mutex;
using std::unique_lock;

template <typename T> class BlockingQueue {
public:
  BlockingQueue() {}
  BlockingQueue(const BlockingQueue &) = delete;
  ~BlockingQueue(){};

  void push(const T &value) {
    unique_lock lock(mtx);
    q.push(value);
    condition.notify_all();
  }

  T take() {
    unique_lock lock(mtx);
    while (q.empty()) {
      condition.wait(lock);
    }

    T value(std::move(q.front()));
    q.pop();
    return value;
  }

  size_t size() const {
    unique_lock lock(mtx);
    return q.size();
  }

private:
  std::queue<T> q;
  std::mutex mtx;
  condition_variable condition;
};

#endif