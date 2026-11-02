// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Internal header: io_uring worker. One RingWorker owns one ring, the
// entries of the FUSE queues assigned to it, and the thread that drives
// them. Session::run() instantiates `uring_threads` of them and divides
// the queues among them.
//
// Lives under namespace fex::detail because it is private to the
// implementation; the public API in <fex/session.hpp> never names it.

#pragma once

#include "session_impl.hpp"

#include <cstddef>
#include <cstdint>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <liburing.h>
#include <sys/uio.h>

namespace fex::detail {

// User-data scheme: the bottom 32 bits hold the entry index (0..K-1
// for FUSE entries, K for the stop poll); we reserve the all-ones
// pattern for the stop poll. The kernel returns the same user_data we
// put in, so we can tell exactly which slot fired.
inline constexpr std::uint64_t kStopSentinel = 0xFFFFFFFFFFFFFFFFull;

class RingWorker {
public:
    RingWorker(Session::Impl& impl, std::vector<unsigned> qids, unsigned depth,
               std::size_t payload_bytes)
        : impl_(impl), qids_(std::move(qids)), depth_(depth),
          payload_bytes_(payload_bytes)
    {}

    ~RingWorker() { teardown(); }

    RingWorker(const RingWorker&)            = delete;
    RingWorker& operator=(const RingWorker&) = delete;
    RingWorker(RingWorker&&)                 = delete;
    RingWorker& operator=(RingWorker&&)      = delete;

    // Initialise the ring, allocate entry buffers, submit REGISTER for
    // each entry and the stop poll. The kernel will hold these SQEs
    // pending until requests arrive (REGISTER) or stop is signalled.
    std::error_code start();

    // Spawn the worker thread.
    void launch() { thread_ = std::thread([this]{ run(); }); }

    // Wait for the worker thread to exit. Stop is signalled centrally
    // via the shared stop_efd; the thread sees the poll completion,
    // breaks out, and returns.
    void join() { if (thread_.joinable()) thread_.join(); }

    // Surface any I/O error captured by the worker thread.
    std::error_code error() const noexcept { return ec_; }

private:
    struct Entry {
        // Each entry has one contiguous region:
        //   [fuse_uring_req_header (288 B)] [payload area (payload_bytes_)]
        // The kernel writes the request into this region (header fields
        // + op_in + ent_in_out + payload); we write the reply by
        // overlaying fuse_out_header in in_out[] and putting reply
        // bytes in the payload area, then submitting COMMIT_AND_FETCH.
        std::byte*    buf       = nullptr;
        std::size_t   buf_len   = 0;
        std::uint64_t commit_id = 0;  // captured from each request
        unsigned      qid       = 0;  // FUSE queue this entry belongs to

        // Stable 2-segment iovec the kernel imports on every
        // REGISTER / COMMIT_AND_FETCH. fuse_uring_create_ring_ent()
        // requires exactly FUSE_URING_IOV_SEGS == 2 segments:
        //   iov[0] -> fuse_uring_req_header region (>= 288 B)
        //   iov[1] -> payload region (>= ring->max_payload_sz)
        // Both segments are slices of `buf`; we keep them per-entry
        // so the address handed to the kernel stays valid until the
        // entry is torn down.
        struct iovec iov[2]{};
    };

    void run();
    void teardown() noexcept;

    // Build the REGISTER SQE for entry `i`. Used on initial arm.
    void prep_register(io_uring_sqe* sqe, std::uint32_t i) noexcept;

    // Build the COMMIT_AND_FETCH SQE for entry `i` carrying a reply.
    // `payload_sz` is the reply payload length (0 on error replies).
    void prep_commit_and_fetch(io_uring_sqe* sqe, std::uint32_t i,
                               std::uint64_t commit_id,
                               std::uint32_t payload_sz) noexcept;

    // Process one request that's just landed in entries_[i].buf.
    // Writes the reply into the same buffer and returns the reply
    // payload size (the kernel reads this from ent_in_out.payload_sz
    // and from fuse_out_header.len).
    std::uint32_t handle_one(std::uint32_t i) noexcept;

    Session::Impl&        impl_;
    std::vector<unsigned> qids_;
    unsigned              depth_;
    std::size_t           payload_bytes_;

    // Body buffer for handler dispatch: reassembles [op_in (128B)] +
    // [payload (payload_sz)] into one contiguous region so the handlers
    // can treat "body" as a flat byte stream after fuse_in_header. One
    // per thread: this thread handles one request at a time.
    std::vector<std::byte> scratch_;

    io_uring             ring_{};
    bool                 ring_inited_ = false;
    std::vector<Entry>   entries_;
    std::thread          thread_;
    std::error_code      ec_;
};

}  // namespace fex::detail
