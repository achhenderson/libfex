// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Internal header shared by the libfex TUs (session.cpp, handlers.cpp,
// mount.cpp, uring_worker.cpp). Not installed; do not include from
// public headers.
//
// Defines:
//   - the Replier struct + reply_* helpers used by every per-opcode
//     handler,
//   - small conversion helpers (split_duration, pack_statx,
//     unpack_statx, neg_errno),
//   - Session::Impl, the type previously hidden in session.cpp.
//
// All names live in `namespace fex`; the Impl members are the actual
// implementation of the public Session class declared in
// <fex/session.hpp>.

#pragma once

#include "fex/abi.h"
#include "fex/session.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace fex {

namespace detail { class Notifier; }

// notify_unique of a FUSE_NOTIFY_RETRIEVE: the cookie shifted past
// FUSE_INT_REQ_BIT, above the unique values the kernel uses.
inline constexpr std::uint64_t kRetrieveUnique = 1ull << 62;

// -----------------------------------------------------------------------
// Replier
//
// Per-opcode handlers fill a Replier instead of writing the fd directly.
// The io_uring transport (uring_worker.cpp) reads `neg_err` and the
// bytes in [out, out+len) and ships them to the kernel.
// -----------------------------------------------------------------------

struct Replier {
    std::byte*    out      = nullptr;  // capacity beyond fuse_out_header
    std::size_t   cap      = 0;
    std::size_t   len      = 0;        // bytes written by the handler
    int           neg_err  = 0;        // negative-errno; if !=0, len is ignored
    std::uint64_t unique   = 0;        // for assembling fuse_out_header
};

inline int neg_errno(Errc e) noexcept {
    return -static_cast<int>(e);
}

inline void reply_error(Replier& r, Errc e) noexcept {
    r.neg_err = neg_errno(e);
    r.len     = 0;
}

inline void reply_ok(Replier& r) noexcept {
    r.neg_err = 0;
    r.len     = 0;
}

inline void reply_payload(Replier& r, std::span<const std::byte> p) noexcept {
    // If a handler tries to overrun the reply buffer we map it to EIO
    // rather than corrupt memory. In practice the buffer is sized for
    // the largest in-flight request (uring_payload_bytes), so this is
    // a defense in depth.
    if (p.size() > r.cap) {
        r.neg_err = -EIO;
        r.len     = 0;
        return;
    }
    if (!p.empty())
        std::memcpy(r.out, p.data(), p.size());
    r.neg_err = 0;
    r.len     = p.size();
}

template <typename T>
inline void reply_pod(Replier& r, const T& pod) noexcept {
    reply_payload(r, std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(&pod), sizeof(pod)});
}

// -----------------------------------------------------------------------
// statx / duration helpers
// -----------------------------------------------------------------------

// fusex protocol passes timeouts as (sec, nsec) pairs.
inline void split_duration(std::chrono::nanoseconds d,
                           std::uint64_t& sec, std::uint32_t& nsec) noexcept {
    if (d.count() < 0) { sec = 0; nsec = 0; return; }
    sec  = static_cast<std::uint64_t>(d.count() / 1'000'000'000);
    nsec = static_cast<std::uint32_t>(d.count() % 1'000'000'000);
}

// pack_statx / unpack_statx live in handlers.cpp; only handlers.cpp
// needs them, so they stay file-local there (anonymous namespace).

// -----------------------------------------------------------------------
// Session::Impl
//
// The public Session class (in <fex/session.hpp>) forward-declares this
// struct and owns it via unique_ptr. Implementation files include this
// header to reach the members.
// -----------------------------------------------------------------------

struct Session::Impl {
    SessionOptions    opts;
    UniqueFd          dev_fd;
    Filesystem*       fs = nullptr;
    UniqueFd          stop_efd;          // eventfd run() waits on
    UniqueFd          ring_stop_efd;     // eventfd the ring workers poll
    std::atomic<bool> stopping{false};   // stop() was called
    std::atomic<bool> worker_gone{false};
    bool              mount_installed = false; // move_mount succeeded; umount on teardown
    std::uint64_t     mount_id = 0;      // to find out if it's still ours
    std::unique_ptr<detail::Notifier> notifier;

    explicit Impl(SessionOptions o);
    ~Impl();

    // Wake run() to shut down. Async-signal-safe.
    void request_stop() noexcept;

    // A worker ended, which can be the connection going away.
    void worker_exited() noexcept;

    // Write back what is dirty while the workers still serve.
    void sync_mount() noexcept;

    // Unmount with MNT_FORCE, which aborts the connection, if the mount
    // at the mountpoint is still ours.
    void detach_mount() noexcept;

    // ----- dispatch -----------------------------------------------------

    // Build a Context from the request header.
    static Context make_ctx(const ::fuse_in_header& h) noexcept {
        Context c;
        c.uid    = h.uid;
        c.gid    = h.gid;
        c.pid    = h.pid;
        c.nodeid = static_cast<NodeId>(h.nodeid);
        c.unique = h.unique;
        return c;
    }

    // Skip the in-extension blob between the header and the per-op
    // arguments. fusex doesn't currently use extensions, but a daemon
    // that survives upstream fuse changes must still account for them.
    template <typename InArg>
    static const InArg* in_arg(const ::fuse_in_header& h,
                               const std::byte* body, std::size_t body_len) noexcept
    {
        const std::size_t ext_bytes = std::size_t{h.total_extlen} * 8u;
        if (ext_bytes + sizeof(InArg) > body_len)
            return nullptr;
        return reinterpret_cast<const InArg*>(body + ext_bytes);
    }

    // Per-opcode handlers (defined in handlers.cpp). Each takes the
    // in-header, a pointer to the first byte after the header, the
    // remaining body length, and the Replier it fills with its reply.
    void handle_init       (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_lookup_root(const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_lookupx    (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_forget     (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_batch_forget(const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_statx      (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_setstatx   (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_mkobjx     (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_unlink     (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&, bool is_rmdir);
    void handle_rename2    (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_link       (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_open       (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_release    (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_read       (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_write      (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_readlink   (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_statfs     (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_fallocate  (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_opendir    (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_releasedir (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_readdir    (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_getxattr   (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_setxattr   (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_listxattr  (const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_removexattr(const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);
    void handle_notify_reply(const ::fuse_in_header&, const std::byte*, std::size_t, Replier&);

    // Pure dispatch: pick the handler by h.opcode and call it. No I/O.
    void dispatch(const ::fuse_in_header& h,
                  const std::byte* body, std::size_t body_len,
                  Replier& r) noexcept;

    // ----- mount (defined in mount.cpp) ---------------------------------
    //
    // Mount is split into two phases so workers can run between them:
    //
    //   Phase 1 (main thread): fsopen + fsconfig(SET_FD).
    //                          Kernel installs the channel into fud.
    //                          Returns the fsfd to use for CMD_CREATE.
    //   Phase 2 (mount thread): fsconfig(CMD_CREATE) + fsmount + move_mount.
    //                          CMD_CREATE blocks while the kernel runs
    //                          INIT/LOOKUP_ROOT/STATX through the rings
    //                          we registered between the two phases.
    //
    // The kernel's channel-install-at-SET_FD support is what lets a daemon
    // submit FUSE_IO_URING_CMD_REGISTER between phase 1 and phase 2; before
    // that change libfex needed a /dev/fuse read()/writev() bootstrap loop
    // for INIT/LOOKUP_ROOT/STATX.
    std::expected<UniqueFd, std::error_code> mount_open_and_set_fd();
    std::error_code mount_create_and_finish(UniqueFd fsfd);
};

}  // namespace fex
