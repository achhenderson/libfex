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
//      Kernel patch installs the channel into fud; the daemon may now
//      submit FUSE_IO_URING_CMD_REGISTER on dev_fd.
//   2. RingWorker::start()  per queue            ← spawn workers
//      Each worker REGISTERs `depth` entries. Once all queues have an
//      entry armed the kernel flips fiq->ops to fuse_io_uring_ops and
//      marks ring->ready.
//   3. fsconfig(CMD_CREATE) + fsmount + move_mount ← phase 2 (helper thread)
//      CMD_CREATE blocks until INIT/LOOKUP_ROOT/STATX have been served
//      via the rings the workers just armed.
//   4. The workers keep running until either the kernel closes the
//      device or stop() writes to the shared stop eventfd.

#include "session_impl.hpp"
#include "uring_worker.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <memory>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

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

Session::Session(SessionOptions opts) : impl_(std::make_unique<Impl>(std::move(opts))) {}
Session::~Session() = default;

int Session::device_fd() const noexcept { return impl_->dev_fd.get(); }

void Session::stop() noexcept {
    impl_->stopping.store(true, std::memory_order_release);
    // Wake every ring worker that's parked in io_uring_wait_cqe(). One
    // counter bump is enough — POLL_ADD on an eventfd is level-
    // triggered, so every armed ring's poll fires.
    if (impl_->stop_efd.valid()) {
        std::uint64_t one = 1;
        [[maybe_unused]] auto n =
            ::write(impl_->stop_efd.get(), &one, sizeof(one));
    }
}

std::error_code Session::run(Filesystem& fs)
{
    impl_->fs = &fs;

    // Scope guard: on every exit path, if move_mount installed the
    // fs into the namespace, drop it. Without this, a daemon that
    // exits (clean stop, signal, crashed worker, …) leaves the
    // kernel superblock attached to the mountpoint — subsequent
    // mounts on the same path stack on top, and tools that look the
    // fs up by source (xfstests' _check_mounted_on, findmnt, …) see
    // duplicates.
    //
    // Teardown ordering (matters for fuse_uring_ent freeing):
    //
    //   1. umount2(MNT_FORCE | MNT_DETACH) — MNT_FORCE drives the
    //      kernel through fuse_umount_begin() → fuse_chan_abort() →
    //      fuse_uring_abort() → fuse_uring_stop_queues() synchronously,
    //      which walks every ring queue and moves all FRRS_AVAILABLE /
    //      FRRS_USERSPACE entries to the queue's ent_released list.
    //      Without MNT_FORCE this only fires later (via fuse_dev_release
    //      when the file ref hits 0, or via the SB destroy path) and
    //      can race with refcount drops, leaving entries stuck on
    //      ent_in_userspace / ent_avail_queue. They then leak when
    //      fuse_uring_destruct() WARN_ON's a non-empty queue and frees
    //      only ent_released. fusex doesn't set fc->destroy, so
    //      MNT_FORCE doesn't trigger any FUSE_DESTROY round-trip; it
    //      just aborts the channel. MNT_DETACH on top makes the
    //      namespace detach lazy so we don't block on busy refs.
    //
    //   2. dev_fd.reset() — close /dev/fuse. The ring workers have
    //      already joined and their io_urings have been torn down by
    //      this point, so no io_uring refs remain on the file. The
    //      userspace close drops the last ref → fuse_dev_release runs,
    //      which calls fuse_conn_put() on the conn ref the channel
    //      took at fuse_dev_install time. With the mount also gone,
    //      fc refcount hits zero and the RCU delayed_release callback
    //      fires fuse_uring_destruct(), which kfree()s every entry
    //      that step 1 moved to ent_released.
    struct UmountOnExit {
        Impl* impl;
        ~UmountOnExit() {
            if (!impl->mount_installed) return;
            if (::umount2(impl->opts.mountpoint.c_str(),
                          MNT_FORCE | MNT_DETACH) < 0) {
                const int e = errno;
                if (e != EINVAL && e != ENOENT) {
                    std::fprintf(stderr,
                        "fex umount(%s): errno=%d (%s)\n",
                        impl->opts.mountpoint.c_str(),
                        e, ::strerror(e));
                }
            }
            impl->dev_fd.reset();
            impl->mount_installed = false;
        }
    } umount_guard{impl_.get()};

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

    {
        int efd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (efd < 0) return {errno, std::system_category()};
        impl_->stop_efd = UniqueFd(efd);
    }

    // ---- 2. Mount phase 1: fsopen + fsconfig(SET_FD). ----------------
    //
    // After SET_FD returns, the kernel has installed a channel into the
    // fud (see kernel patch in fs/fuse/fusex.c::fusex_parse_param). The
    // daemon may now submit FUSE_IO_URING_CMD_REGISTER cmds on dev_fd.
    auto fsfd_or_err = impl_->mount_open_and_set_fd();
    if (!fsfd_or_err) return fsfd_or_err.error();
    UniqueFd fsfd = std::move(*fsfd_or_err);

    // ---- 3. Spawn ring workers BEFORE CMD_CREATE. --------------------
    //
    // start() submits one REGISTER per entry; once all queues have an
    // entry armed, the kernel flips fiq->ops to fuse_io_uring_ops and
    // ring->ready=true. launch() spawns the per-queue worker thread so
    // CQEs (including the kernel's INIT delivered through phase 4 below)
    // are picked up.
    unsigned nqueues = impl_->opts.uring_queues;
    if (nqueues == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        nqueues = std::clamp<unsigned>(hw ? hw : 4, 1, 32);
    }

    std::vector<std::unique_ptr<detail::RingWorker>> workers;
    workers.reserve(nqueues);

    std::error_code worker_start_ec;
    for (unsigned q = 0; q < nqueues; ++q) {
        auto w = std::make_unique<detail::RingWorker>(
            *impl_, q,
            impl_->opts.uring_queue_depth,
            impl_->opts.uring_payload_bytes);
        if (auto ec = w->start()) {
            std::fprintf(stderr, "fex worker[qid=%u]: start failed: %s\n",
                         q, ec.message().c_str());
            worker_start_ec = ec;
            break;
        }
        workers.push_back(std::move(w));
    }
    std::fprintf(stderr, "fex: %u ring workers launched (depth=%u)\n",
                 nqueues, impl_->opts.uring_queue_depth);

    if (worker_start_ec) {
        // Ring setup failed mid-way; we haven't done CMD_CREATE yet so
        // there's nothing to unmount. Just tear down the workers.
        stop();
        for (auto& w : workers) w->join();
        return worker_start_ec;
    }

    for (auto& w : workers) w->launch();

    // ---- 4. Mount phase 2: CMD_CREATE + fsmount + move_mount. --------
    //
    // CMD_CREATE blocks inside the kernel waiting for INIT/LOOKUP_ROOT/
    // STATX replies, which the workers spawned above will serve via
    // the rings. We run this on a helper thread purely so Session::run()
    // can later wait for the workers and the mount completion on the
    // same thread of control.
    std::error_code mount_ec;
    std::thread mounter([&, fsfd = std::move(fsfd)]() mutable {
        mount_ec = impl_->mount_create_and_finish(std::move(fsfd));
        if (mount_ec)
            impl_->stopping.store(true, std::memory_order_release);
    });
    mounter.join();

    if (mount_ec) {
        // Mount failed after rings were registered; stop workers and
        // unwind.
        stop();
        for (auto& w : workers) w->join();
        return mount_ec;
    }
    if (impl_->stopping.load(std::memory_order_acquire)) {
        for (auto& w : workers) w->join();
        return {};
    }
    if (!impl_->init_done) {
        // CMD_CREATE returned success but a worker never executed
        // handle_init? Defensive: shouldn't happen because fill_super
        // wouldn't have returned without an INIT reply.
        stop();
        for (auto& w : workers) w->join();
        return {};
    }

    // ---- 5. Wait for workers to drain. -------------------------------
    //
    // stop() may be called from a signal handler or another thread; the
    // workers exit when they see the stop eventfd or the kernel returns
    // -ENOTCONN on a fetch. We just join.
    for (auto& w : workers) w->join();

    // Surface the first worker error, if any.
    std::error_code worker_ec;
    for (auto& w : workers) {
        if (auto ec = w->error()) { worker_ec = ec; break; }
    }
    fs.destroy();
    return worker_ec;
}

}  // namespace fex
