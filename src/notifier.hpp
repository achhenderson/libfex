// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Internal header: delivers server-initiated notifications to the kernel
// over FUSE_IO_URING_CMD_NOTIFY on a ring of its own.
//
// A notification can wait for a request in flight on a ring worker (an
// invalidation waits for the folio lock held by a READ), so it must not
// run on a worker thread. The kernel punts the command to io-wq and this
// thread only waits for the completion, one notification at a time, which
// also keeps them in the order they were issued.

#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <future>
#include <mutex>
#include <system_error>
#include <thread>
#include <vector>

#include <liburing.h>

namespace fex::detail {

class Notifier {
public:
    Notifier() = default;
    ~Notifier() { stop(); }

    Notifier(const Notifier&)            = delete;
    Notifier& operator=(const Notifier&) = delete;

    std::error_code start(int dev_fd);

    // Queue a notification. The future gets the kernel's result; it is
    // ready with ENOTCONN when the notifier isn't running.
    std::future<std::error_code> post(int code, std::vector<std::byte> payload);

    // Refuse new notifications, fail the queued ones and end the thread.
    // Idempotent. Gives the one in flight a few seconds, which needs the
    // workers to still be serving: it can wait for a request of theirs.
    // After that it is abandoned, see deliver().
    void stop() noexcept;

private:
    struct Msg;

    void run();
    bool deliver(Msg* m);

    int                     dev_fd_ = -1;
    io_uring                ring_{};
    bool                    ring_inited_ = false;
    std::thread             thread_;

    std::mutex              mu_;
    std::condition_variable cv_;
    std::condition_variable finished_cv_;
    std::deque<Msg*>        queue_;
    bool                    running_   = false;
    bool                    stopping_  = false;
    bool                    finished_  = false;
    bool                    abandoned_ = false;
    std::chrono::steady_clock::time_point deadline_{};
};

}  // namespace fex::detail
