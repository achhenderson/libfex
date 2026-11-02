// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Session lifecycle: device fd acquisition, the public Session class
// (ctor/dtor/run/stop/device_fd), and the orchestration that wires
// mount phases together with the ring workers.
//
// Per-opcode handling lives in handlers.cpp; the mount syscalls live
// in mount.cpp; the io_uring worker lives in uring_worker.{hpp,cpp}.
// This file is just the conductor.
//
// Transport model recap (full prose is in <fex/session.hpp>):
//
//   1. fsopen("fusex") + fsconfig(SET_FD)        ← phase 1 (main thread)
//      The kernel installs the channel into fud; the daemon may now
//      submit FUSE_IO_URING_CMD_REGISTER on dev_fd.
//   2. RingWorker::start()  per thread           ← spawn workers
//      Each worker REGISTERs `depth` entries for each of its queues.
//      Once all queues have an entry armed the kernel marks ring->ready.
//   3. fsconfig(CMD_CREATE) + fsmount + move_mount ← phase 2 (helper thread)
//      CMD_CREATE blocks until INIT/LOOKUP_ROOT/STATX have been served
//      via the rings the workers just armed.
//   4. The workers keep running until the connection goes away, which
//      an unmount does, or until stop(), which writes back what is dirty
//      and then unmounts.

#include "notifier.hpp"
#include "session_impl.hpp"
#include "uring_worker.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <expected>
#include <fstream>
#include <future>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x4000U
#endif

namespace fex {

// -----------------------------------------------------------------------
// UniqueFd
// -----------------------------------------------------------------------

UniqueFd::~UniqueFd() { reset(); }

UniqueFd& UniqueFd::operator=(UniqueFd&& o) noexcept {
    if (this != &o) {
        reset(o.fd_);
        o.fd_ = -1;
    }
    return *this;
}

void UniqueFd::reset(int fd) noexcept {
    if (fd_ >= 0 && fd_ != fd) {
        // close(2) cannot meaningfully fail here; even EINTR doesn't
        // leave the fd open on Linux.
        ::close(fd_);
    }
    fd_ = fd;
}

// -----------------------------------------------------------------------
// open_fex_device(): open /dev/fuse + flip the sync-INIT bit. fusex
// rejects any device fd that isn't marked sync-INIT.
// -----------------------------------------------------------------------

std::expected<UniqueFd, std::error_code> open_fex_device() {
    int fd = ::open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return std::unexpected(std::error_code(errno, std::system_category()));
    UniqueFd ufd(fd);

    if (::ioctl(fd, FUSE_DEV_IOC_SYNC_INIT) < 0) {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    return ufd;
}

// =======================================================================
//                                Session
// =======================================================================

Session::Impl::Impl(SessionOptions o)
    : opts(std::move(o)), notifier(std::make_unique<detail::Notifier>()) {}

Session::Impl::~Impl() = default;

namespace {

void wake(const UniqueFd& efd) noexcept {
    if (efd.valid()) {
        std::uint64_t one = 1;
        [[maybe_unused]] auto n = ::write(efd.get(), &one, sizeof(one));
    }
}

}  // anonymous

void Session::Impl::request_stop() noexcept {
    stopping.store(true, std::memory_order_release);
    wake(stop_efd);
}

void Session::Impl::worker_exited() noexcept {
    worker_gone.store(true, std::memory_order_release);
    wake(stop_efd);
}

void Session::Impl::sync_mount() noexcept {
    // O_PATH won't do for syncfs(). This is why it isn't kept open from the
    // mount on, too: that would make every unmount from the outside EBUSY.
    const int fd = ::open(opts.mountpoint.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return;
    struct ::statx stx;
    if (::statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC, STATX_MNT_ID_UNIQUE, &stx) == 0 &&
        (stx.stx_mask & STATX_MNT_ID_UNIQUE) && stx.stx_mnt_id == mount_id &&
        ::syncfs(fd) < 0) {
        const int e = errno;
        std::fprintf(stderr, "fex syncfs(%s): errno=%d (%s)\n",
                     opts.mountpoint.c_str(), e, ::strerror(e));
    }
    ::close(fd);
}

void Session::Impl::detach_mount() noexcept {
    if (!mount_installed)
        return;
    mount_installed = false;

    // After an unmount from the outside something else can be at the
    // mountpoint, even a new mount of this daemon.
    struct ::statx stx;
    if (::statx(AT_FDCWD, opts.mountpoint.c_str(), AT_STATX_DONT_SYNC,
                STATX_MNT_ID_UNIQUE, &stx) < 0 ||
        !(stx.stx_mask & STATX_MNT_ID_UNIQUE) || stx.stx_mnt_id != mount_id)
        return;

    // MNT_FORCE aborts the connection, which ends all the requests nobody
    // will serve any more. MNT_DETACH makes the detach lazy so we don't
    // block on busy refs.
    if (::umount2(opts.mountpoint.c_str(), MNT_FORCE | MNT_DETACH) < 0) {
        const int e = errno;
        if (e != EINVAL && e != ENOENT) {
            std::fprintf(stderr, "fex umount(%s): errno=%d (%s)\n",
                         opts.mountpoint.c_str(), e, ::strerror(e));
        }
    }
}

Session::Session(SessionOptions opts) : impl_(std::make_unique<Impl>(std::move(opts))) {}
Session::~Session() = default;

int Session::device_fd() const noexcept { return impl_->dev_fd.get(); }

void Session::stop() noexcept { impl_->request_stop(); }

namespace {

// The kernel has one FUSE queue per possible CPU (fuse_uring_create()) and
// doesn't serve anything until each of them has an entry, CPUs that are
// offline included. The file holds ranges like "0-7,16-23".
unsigned possible_cpus() {
    unsigned count = 0;
    std::ifstream in("/sys/devices/system/cpu/possible");
    std::string line, part;
    if (std::getline(in, line)) {
        std::stringstream ss(line);
        while (std::getline(ss, part, ',')) {
            unsigned a = 0, b = 0;
            const int n = std::sscanf(part.c_str(), "%u-%u", &a, &b);
            if (n == 1)
                count += 1;
            else if (n == 2 && b >= a)
                count += b - a + 1;
        }
    }
    if (count == 0) {
        const long n = ::sysconf(_SC_NPROCESSORS_CONF);
        count = n > 0 ? static_cast<unsigned>(n) : 1;
    }
    return count;
}

}  // anonymous

std::error_code Session::run(Filesystem& fs)
{
    impl_->fs = &fs;

    // For the exits before the mount thread exists, idempotent after that.
    struct ExitGuard {
        Impl* impl;
        ~ExitGuard() {
            impl->notifier->stop();
            impl->dev_fd.reset();
        }
    } exit_guard{impl_.get()};

    // ---- 1. Acquire dev fd and stop eventfd. -------------------------
    if (impl_->opts.dev_fd >= 0) {
        impl_->dev_fd = UniqueFd(impl_->opts.dev_fd);
        impl_->opts.dev_fd = -1;
        // Caller-supplied fd must already be sync-INIT'd.
    } else {
        auto dev = open_fex_device();
        if (!dev) return dev.error();
        impl_->dev_fd = std::move(*dev);
    }

    for (UniqueFd* efd : {&impl_->stop_efd, &impl_->ring_stop_efd}) {
        int fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (fd < 0) return {errno, std::system_category()};
        *efd = UniqueFd(fd);
    }
    // stop() before this point didn't wake anybody.
    if (impl_->stopping.load(std::memory_order_acquire))
        impl_->request_stop();

    // ---- 2. Mount phase 1: fsopen + fsconfig(SET_FD). ----------------
    //
    // After SET_FD returns, the kernel has created the connection and
    // installed its channel into the fud (fusex_parse_param). The daemon
    // may now submit FUSE_IO_URING_CMD_* on dev_fd.
    auto fsfd_or_err = impl_->mount_open_and_set_fd();
    if (!fsfd_or_err) return fsfd_or_err.error();
    UniqueFd fsfd = std::move(*fsfd_or_err);

    if (auto ec = impl_->notifier->start(impl_->dev_fd.get()))
        return ec;

    // ---- 3. Spawn ring workers BEFORE CMD_CREATE. --------------------
    //
    // start() submits one REGISTER per entry; once all queues have an
    // entry armed, the kernel starts serving requests over the rings.
    // launch() spawns the worker threads so CQEs (including the kernel's
    // INIT delivered through phase 4 below) are picked up.
    const unsigned nqueues = possible_cpus();
    unsigned nthreads = impl_->opts.uring_threads;
    if (nthreads == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        nthreads = std::clamp<unsigned>(hw ? hw : 4, 1, 32);
    }
    nthreads = std::min(nthreads, nqueues);

    std::vector<std::vector<unsigned>> qids(nthreads);
    for (unsigned q = 0; q < nqueues; ++q)
        qids[q % nthreads].push_back(q);

    std::vector<std::unique_ptr<detail::RingWorker>> workers;
    workers.reserve(nthreads);

    for (unsigned t = 0; t < nthreads; ++t) {
        auto w = std::make_unique<detail::RingWorker>(
            *impl_, std::move(qids[t]),
            impl_->opts.uring_queue_depth,
            impl_->opts.uring_payload_bytes);
        if (auto ec = w->start()) {
            // Haven't done CMD_CREATE yet so there's nothing to unmount.
            std::fprintf(stderr, "fex worker %u: start failed: %s\n",
                         t, ec.message().c_str());
            return ec;
        }
        workers.push_back(std::move(w));
    }
    std::fprintf(stderr, "fex: %u ring workers launched (queues=%u depth=%u)\n",
                 nthreads, nqueues, impl_->opts.uring_queue_depth);

    for (auto& w : workers) w->launch();

    // ---- 4. Mount phase 2: CMD_CREATE + fsmount + move_mount. --------
    //
    // CMD_CREATE blocks inside the kernel waiting for INIT/LOOKUP_ROOT/
    // STATX replies, which the workers spawned above serve via the
    // rings, so it can't run on a thread that has to serve them.
    std::error_code mount_ec;
    std::atomic<bool> mount_done{false};
    std::thread mounter([&, fsfd = std::move(fsfd)]() mutable {
        mount_ec = impl_->mount_create_and_finish(std::move(fsfd));
        mount_done.store(true, std::memory_order_release);
        if (mount_ec)
            impl_->request_stop();
    });

    // ---- 5. Wait for the end. ----------------------------------------
    //
    // That is stop(), a failed mount, or a worker that ended: because of
    // the unmount from the outside, an abort of the connection or an error.
    {
        struct pollfd pfd{.fd = impl_->stop_efd.get(), .events = POLLIN, .revents = 0};
        while (::poll(&pfd, 1, -1) < 0 && errno == EINTR) {}
    }

    // ---- 6. Shut down. -----------------------------------------------
    //
    // The order matters, everything here waits for what comes before it:
    //
    //   1. Write back what is dirty: nothing writes it back on close, and
    //      this needs the workers. If the server hangs it can't be helped,
    //      the abort below ends the sync.
    //   2. The notifier, whose last notification can need the workers too.
    //   3. Abort the connection, if the mount is still at the mountpoint.
    //   4. The workers.
    //   5. Close the rings and the device. That aborts the connection if
    //      step 3 couldn't: it is not mounted yet, or has moved.
    //   6. The mount thread, which can only be stuck in CMD_CREATE until
    //      that abort. It may have got through in the meantime.
    const bool mounted = mount_done.load(std::memory_order_acquire);
    std::thread syncer;
    if (mounted && !mount_ec && impl_->stopping.load(std::memory_order_acquire) &&
        !impl_->worker_gone.load(std::memory_order_acquire)) {
        auto synced = std::make_shared<std::promise<void>>();
        auto fut = synced->get_future();
        syncer = std::thread([this, synced] {
            impl_->sync_mount();
            synced->set_value();
        });
        if (fut.wait_for(std::chrono::seconds(30)) != std::future_status::ready)
            std::fprintf(stderr, "fex: giving up on writing back the dirty data\n");
    }

    impl_->notifier->stop();

    if (mounted)
        impl_->detach_mount();

    wake(impl_->ring_stop_efd);
    for (auto& w : workers) w->join();

    // Surface the first worker error, if any.
    std::error_code worker_ec;
    for (auto& w : workers) {
        if (auto ec = w->error()) { worker_ec = ec; break; }
    }

    workers.clear();
    impl_->dev_fd.reset();

    mounter.join();
    impl_->detach_mount();
    if (syncer.joinable())
        syncer.join();

    if (worker_ec) return worker_ec;
    if (mount_ec) return mount_ec;

    fs.destroy();
    return {};
}

}  // namespace fex
