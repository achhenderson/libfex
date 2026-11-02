// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// fex/session.hpp - high-level entry point.
//
// A Session owns:
//   - the open /dev/fuse fd,
//   - the mount (set up via fsopen/fsconfig/fsmount/move_mount),
//   - a pool of per-queue io_uring rings that carry every post-INIT
//     request and reply.
//
// Transport: every request and reply travels over FUSE-over-io_uring
// (`IORING_OP_URING_CMD` with `FUSE_IO_URING_CMD_REGISTER` /
// `FUSE_IO_URING_CMD_COMMIT_AND_FETCH`), including the mount-time
// handshake (INIT / LOOKUP_ROOT / STATX). The daemon registers ring
// entries between `fsconfig(SET_FD)` and `fsconfig(CMD_CREATE)`, and
// the kernel's `fusex_fill_super` then routes INIT through the rings
// like any other request. `/dev/fuse` is the channel fd that carries
// the URING_CMD opcodes; `read()`/`write()` on it fail for a fusex
// connection.
//
// Concurrency: the kernel has one FUSE queue per possible CPU. There are
// `uring_threads` worker threads, each owning one ring with
// `uring_queue_depth` entries for each of the queues assigned to it.
// Callbacks may run concurrently on all the workers — `Filesystem`
// implementations must be thread-safe.
//
// Typical use:
//
//     MyFilesystem fs{...};
//     fex::Session s(fex::SessionOptions{
//         .mountpoint = "/mnt/myfs",
//         .fsname     = "myfs",
//     });
//     s.run(fs);                  // blocks until unmount
//
// `run()` is the foreground entry; `stop()` from another thread (or a
// signal handler) makes it write back what is dirty and unmount.

#pragma once

#include "filesystem.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace fex {

// Owning RAII wrapper for a Unix fd. Exposed because callers occasionally
// want to peek at the dev fd (e.g. to clone it for an io_uring channel
// once that support lands).
class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd();

    UniqueFd(const UniqueFd&)            = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    UniqueFd& operator=(UniqueFd&& o) noexcept;

    int  get() const noexcept { return fd_; }
    int  release() noexcept   { int r = fd_; fd_ = -1; return r; }
    bool valid() const noexcept { return fd_ >= 0; }
    void reset(int fd = -1) noexcept;

private:
    int fd_ = -1;
};

struct SessionOptions {
    // Where to mount. Must already exist and be a directory.
    std::string mountpoint;

    // Optional human-readable source label (shows in /proc/self/mountinfo).
    std::string fsname = "fex";

    // Mount source string — what appears in the first column of
    // `mount`(8) / `/proc/self/mountinfo`. If left empty, the kernel
    // records "none". Typical use is the backing path for passthrough
    // FSes, or a server URL for network FSes.
    std::string source;

    // Mount the FS read-only.
    bool read_only = false;

    // If non-empty, an already-open fd to /dev/fuse; the Session takes
    // ownership. If <0 (default), the Session opens /dev/fuse itself.
    // Useful for test harnesses that pre-clone fds.
    int  dev_fd = -1;

    // ---- io_uring transport ------------------------------------------
    // Each ring is polled by its own worker thread; this is how the
    // session achieves multi-threaded dispatch. The kernel needs entries
    // on all its queues (one per possible CPU), they are divided among
    // the threads.

    // Number of worker threads and rings. 0 means "pick
    // `std::thread::hardware_concurrency()`, clamped to [1, 32]".
    unsigned uring_threads = 0;

    // Entries per FUSE queue. The kernel keeps this many requests in
    // flight per queue. Each entry maps a request buffer of size
    // `uring_payload_bytes + sizeof(fuse_uring_req_header)`, which only
    // takes memory once a request lands on it.
    unsigned uring_queue_depth = 32;

    // Per-entry payload area. Caps the largest single READ/WRITE the
    // daemon will accept. The INIT handler advertises max_pages such
    // that one request fits in this many bytes.
    std::size_t uring_payload_bytes = 1u << 20;   // 1 MiB
};

class Session {
public:
    explicit Session(SessionOptions opts);
    ~Session();

    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    // Mount, run, and join the request workers. Returns when:
    //  - the kernel closes the device (umount), or
    //  - stop() was called, or
    //  - an unrecoverable I/O error occurred.
    //
    // On entry, performs sync-INIT: ioctl(FUSE_DEV_IOC_SYNC_INIT),
    // spawns `opts.uring_threads` ring workers, mounts via fsopen/
    // fsconfig/fsmount (the workers serve the kernel's INIT/LOOKUP_ROOT/
    // STATX handshake) and blocks until the workers exit. Filesystem
    // callbacks may run concurrently on any worker thread — implementations
    // must be thread-safe.
    //
    // Errors during the handshake abort run() with the mount torn down.
    std::error_code run(Filesystem& fs);

    // Asynchronous request to wind down: run() writes back what is dirty,
    // unmounts, and returns. Safe to call from a signal handler — it's
    // just an atomic store and an eventfd write.
    void stop() noexcept;

    // Inspect the dev fd (e.g., for diagnostics). Nothing reads from it,
    // the workers own their rings.
    int device_fd() const noexcept;

    // ---- Notifications ------------------------------------------------
    //
    // The kernel keeps names, attributes and data until the daemon tells
    // it they changed, there are no timeouts. These send that message.
    //
    // Usable from any thread, also from Filesystem callbacks, while run()
    // is running. They queue the notification and return; the kernel
    // handles them one at a time, in the order they were issued. The
    // future gets the kernel's result, ENOTCONN if the session isn't
    // running. ENOENT means the kernel doesn't have that object cached,
    // so there was nothing to do.
    //
    // Don't wait for the future in a callback: an invalidation can wait
    // for a request that is in flight on the same thread.

    // Forget the attributes of `nodeid`: the next use fetches them with
    // statx(). With offset >= 0 also drop its cached data from `offset`,
    // `length` bytes or to the end if length <= 0. Dirty data is written
    // back first. For a directory this also drops the readdir cache.
    std::future<std::error_code>
    notify_inval_inode(NodeId nodeid, std::int64_t offset = 0, std::int64_t length = 0);

    // Forget a name in `parent`, positive or negative. Only does something
    // if the kernel has that name cached: for a name that is new in a
    // directory also invalidate the directory for the readdir cache.
    std::future<std::error_code>
    notify_inval_entry(NodeId parent, std::string_view name);

    // Same as notify_inval_entry(), and the object `child` lost that name:
    // the kernel drops its link count too. Fails with ENOENT if the name
    // refers to another object.
    std::future<std::error_code>
    notify_delete(NodeId parent, NodeId child, std::string_view name);

    // Put data into the page cache of a regular file `nodeid`, growing it
    // if it ends beyond EOF. The copy in the daemon stays authoritative:
    // this doesn't make the kernel write it back.
    std::future<std::error_code>
    notify_store(NodeId nodeid, std::uint64_t offset, std::span<const std::byte> data);

    // Ask for up to `size` bytes from the page cache of a regular file
    // `nodeid`. What is cached arrives at Filesystem::retrieve_reply()
    // with this `cookie`, which has to be below 2^61. The future only says
    // that the request was accepted.
    std::future<std::error_code>
    notify_retrieve(NodeId nodeid, std::uint64_t offset, std::uint32_t size,
                    std::uint64_t cookie);

    // Drop the unused cached names of these objects, so that the ones with
    // no name left and no user get their FORGET.
    std::future<std::error_code> notify_prune(std::span<const NodeId> nodeids);

    // Defined in session.cpp. The struct is exposed (but not its
    // members) because the in-TU RingWorker holds a reference.
    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

// Convenience: open /dev/fuse and perform the sync-INIT ioctl. Useful
// when callers want to do the mount themselves and just need a properly
// prepared device fd.
std::expected<UniqueFd, std::error_code> open_fex_device();

}  // namespace fex
