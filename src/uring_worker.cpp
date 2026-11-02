// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// io_uring worker. Each RingWorker owns one io_uring instance and the
// entries of its FUSE queues. The thread's job is to keep `queue_depth`
// entries per queue armed (kernel-side) at all times: every time a CQE
// arrives the worker processes the request and immediately submits
// FUSE_IO_URING_CMD_COMMIT_AND_FETCH on the same SQE to post the reply
// AND re-arm for the next request. The only way out of the loop is the
// shared ring stop eventfd, which every ring has armed via
// IORING_OP_POLL_ADD, or the kernel ending the connection.

#include "uring_worker.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <utility>

#include <poll.h>
#include <sys/mman.h>
#include <sys/prctl.h>

namespace fex::detail {

namespace {

constexpr std::uint64_t make_ud(std::uint32_t entry_idx) noexcept {
    return static_cast<std::uint64_t>(entry_idx);
}

}  // anonymous

void RingWorker::prep_register(io_uring_sqe* sqe, std::uint32_t i) noexcept
{
    auto& e = entries_[i];
    io_uring_prep_rw(IORING_OP_URING_CMD, sqe, impl_.dev_fd.get(),
                     nullptr, 0, 0);
    sqe->cmd_op = FUSE_IO_URING_CMD_REGISTER;
    // fuse_uring_get_iovec_from_sqe() requires sqe->len ==
    // FUSE_URING_IOV_SEGS (= 2) and reads sqe->addr as a userspace
    // pointer to that iovec array (iov[0]=header, iov[1]=payload).
    // The kernel imports it via import_iovec() — no buffer
    // pre-registration is involved.
    sqe->addr = reinterpret_cast<std::uint64_t>(&e.iov[0]);
    sqe->len  = 2;

    auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
    std::memset(cmd, 0, sizeof(*cmd));
    cmd->qid = static_cast<std::uint16_t>(e.qid);

    io_uring_sqe_set_data64(sqe, make_ud(i));
}

void RingWorker::prep_commit_and_fetch(io_uring_sqe* sqe, std::uint32_t i,
                                       std::uint64_t commit_id,
                                       std::uint32_t /*payload_sz*/) noexcept
{
    auto& e = entries_[i];
    io_uring_prep_rw(IORING_OP_URING_CMD, sqe, impl_.dev_fd.get(),
                     nullptr, 0, 0);
    sqe->cmd_op = FUSE_IO_URING_CMD_COMMIT_AND_FETCH;
    // Same 2-segment iovec convention as REGISTER.
    sqe->addr = reinterpret_cast<std::uint64_t>(&e.iov[0]);
    sqe->len  = 2;

    auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
    std::memset(cmd, 0, sizeof(*cmd));
    cmd->qid       = static_cast<std::uint16_t>(e.qid);
    cmd->commit_id = commit_id;

    io_uring_sqe_set_data64(sqe, make_ud(i));
}

std::error_code RingWorker::start()
{
    // Pre-allocate all entry buffers up front; if any allocation
    // fails we tear down everything (entries_ is owning).
    entries_.resize(qids_.size() * depth_);
    for (std::size_t i = 0; i < entries_.size(); ++i)
        entries_[i].qid = qids_[i / depth_];
    const std::size_t buf_len = sizeof(::fuse_uring_req_header) + payload_bytes_;
    for (auto& e : entries_) {
        // Page-align so the kernel's copy_to_user paths stay happy on
        // large transfers. We over-allocate by one page for simplicity
        // (a posix_memalign would be tighter; mmap keeps it portable).
        void* p = ::mmap(nullptr, buf_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return {errno, std::system_category()};
        e.buf     = static_cast<std::byte*>(p);
        e.buf_len = buf_len;
        // iov[0] = header, iov[1] = payload (slices of `buf`).
        e.iov[0].iov_base = e.buf;
        e.iov[0].iov_len  = sizeof(::fuse_uring_req_header);
        e.iov[1].iov_base = e.buf + sizeof(::fuse_uring_req_header);
        e.iov[1].iov_len  = payload_bytes_;
    }
    // 128B op_in fits in any case; the variable part is the trailing
    // payload.
    scratch_.resize(FUSE_URING_OP_IN_OUT_SZ + payload_bytes_);

    // FUSE-over-io_uring requires both SQE128 and CQE32:
    //   - SQE128: fuse_uring_cmd_req lives in the SQE cmd area, which
    //     only has 16 bytes in a normal SQE.
    //   - CQE32:  the kernel's fuse_uring_register() rejects with
    //     -EINVAL if IO_URING_F_CQE32 isn't set on the cmd.
    // Every entry can have a completion outstanding, plus the stop poll.
    // The REGISTERs are submitted in batches if the SQ is smaller.
    const unsigned total = static_cast<unsigned>(entries_.size()) + 1;
    const unsigned ring_entries = std::min(total, 4096u);
    io_uring_params params{};
    params.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32 |
                   IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;
    params.cq_entries = std::max(total, 2 * ring_entries);
    int rc = io_uring_queue_init_params(ring_entries, &ring_, &params);
    if (rc < 0)
        return {-rc, std::system_category()};
    ring_inited_ = true;

    // Submit one POLL_ADD on the stop eventfd, tagged with the stop
    // sentinel. The kernel never completes this until run() writes
    // to the eventfd, at which point every ring's poll fires.
    {
        io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) return {EAGAIN, std::system_category()};
        io_uring_prep_poll_add(sqe, impl_.ring_stop_efd.get(), POLLIN);
        io_uring_sqe_set_data64(sqe, kStopSentinel);
    }

    // REGISTER each entry. The kernel keeps these pending until a
    // request shows up on this queue, then completes the matching SQE
    // with the request laid out in the entry buffer.
    for (std::uint32_t i = 0; i < entries_.size(); ++i) {
        io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) {
            rc = io_uring_submit(&ring_);
            if (rc < 0)
                return {-rc, std::system_category()};
            sqe = io_uring_get_sqe(&ring_);
        }
        if (!sqe) return {EAGAIN, std::system_category()};
        prep_register(sqe, i);
    }

    rc = io_uring_submit(&ring_);
    if (rc < 0)
        return {-rc, std::system_category()};

    return {};
}

std::uint32_t RingWorker::handle_one(std::uint32_t i) noexcept
{
    Entry& e = entries_[i];
    auto* req = reinterpret_cast<::fuse_uring_req_header*>(e.buf);

    // Kernel request layout:
    //   in_out[0..40]              -> fuse_in_header
    //   op_in[0..in_args[0].size]  -> first in_arg
    //   ring_ent_in_out.payload_sz -> in_args[1..] in the payload area
    e.commit_id = req->ring_ent_in_out.commit_id;
    const std::uint32_t payload_sz = req->ring_ent_in_out.payload_sz;

    const auto* h = reinterpret_cast<const ::fuse_in_header*>(req->in_out);
    ::fuse_in_header h_copy = *h;  // reply clobbers in_out

    // in_args[0].size is derivable from the request — it's whatever's
    // left after the header and the payload. Assemble the body as one
    // contiguous [in_args[0]][in_args[1..]] span; handlers then index
    // past in_args[0] using sizeof(its first in_arg struct).
    const std::size_t first_arg_sz =
        h_copy.len >= sizeof(::fuse_in_header) + payload_sz
            ? h_copy.len - sizeof(::fuse_in_header) - payload_sz
            : 0u;
    const std::size_t body_len = first_arg_sz + payload_sz;

    if (first_arg_sz > FUSE_URING_OP_IN_OUT_SZ ||
        body_len > scratch_.size()) {
        auto* outh = reinterpret_cast<::fuse_out_header*>(req->in_out);
        outh->unique = h_copy.unique;
        outh->error  = -EIO;
        outh->len    = sizeof(::fuse_out_header);
        req->ring_ent_in_out.payload_sz = 0;
        return 0;
    }

    if (first_arg_sz)
        std::memcpy(scratch_.data(), req->op_in, first_arg_sz);
    if (payload_sz)
        std::memcpy(scratch_.data() + first_arg_sz,
                    e.buf + sizeof(::fuse_uring_req_header),
                    payload_sz);

    Replier r;
    r.out    = e.buf + sizeof(::fuse_uring_req_header);
    r.cap    = payload_bytes_;
    r.unique = h_copy.unique;

    impl_.dispatch(h_copy, scratch_.data(), body_len, r);

    // Write the reply header on top of the in_out region.
    auto* outh = reinterpret_cast<::fuse_out_header*>(req->in_out);
    outh->unique = r.unique;
    outh->error  = r.neg_err;
    outh->len    = static_cast<std::uint32_t>(
        sizeof(::fuse_out_header) + (r.neg_err ? 0u : r.len));

    const std::uint32_t reply_sz =
        r.neg_err ? 0u : static_cast<std::uint32_t>(r.len);
    req->ring_ent_in_out.payload_sz = reply_sz;
    return reply_sz;
}

void RingWorker::run()
{
    // Requests for this mount can depend on this thread making progress, so
    // its memory allocations must not reclaim from filesystems or wait for
    // dirty pages. Needs CAP_SYS_RESOURCE, which a root daemon has.
    (void)::prctl(PR_SET_IO_FLUSHER, 1, 0, 0, 0);

    bool stop = false;
    while (!stop) {
        io_uring_cqe* cqe = nullptr;
        int rc = io_uring_wait_cqe(&ring_, &cqe);
        if (rc < 0) {
            if (rc == -EINTR) continue;
            ec_ = {-rc, std::system_category()};
            break;
        }

        const std::uint64_t ud = io_uring_cqe_get_data64(cqe);
        const std::int32_t  res = cqe->res;
        io_uring_cqe_seen(&ring_, cqe);

        if (ud == kStopSentinel) {
            // Stop signalled. We deliberately do NOT try to drain or
            // commit any in-flight entries: the kernel side cancels
            // pending URING_CMDs when the device closes, and our
            // teardown closes the ring. Any half-built replies are
            // discarded by the kernel along with the entries.
            stop = true;
            break;
        }

        const auto idx = static_cast<std::uint32_t>(ud);
        if (idx >= entries_.size()) {
            // Shouldn't happen; if it does, log via ec_ and continue.
            ec_ = {EINVAL, std::system_category()};
            continue;
        }

        if (res < 0) {
            // The filesystem is being torn down, or the connection was
            // aborted, or this task's commands were cancelled.
            if (res == -ENOTCONN || res == -ENODEV ||
                res == -ECONNABORTED || res == -ECANCELED) {
                stop = true;
                break;
            }
            if (res == -EINTR) {
                // Re-arm the slot with another REGISTER.
                io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
                if (sqe) { prep_register(sqe, idx); io_uring_submit(&ring_); }
                continue;
            }
            // Other errors: surface and stop.
            std::fprintf(stderr,
                "fex worker[qid=%u]: CQE res=%d (%s) for entry idx=%u\n",
                entries_[idx].qid, res, ::strerror(-res), idx);
            ec_ = {-res, std::system_category()};
            stop = true;
            break;
        }

        // Successful fetch — a request landed in entries_[idx]. Run it
        // and immediately submit COMMIT_AND_FETCH to ship the reply
        // and re-arm the slot.
        std::uint32_t reply_sz = handle_one(idx);
        io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) {
            // SQ full. Submit pending and retry once.
            io_uring_submit(&ring_);
            sqe = io_uring_get_sqe(&ring_);
        }
        if (!sqe) {
            ec_ = {EAGAIN, std::system_category()};
            stop = true;
            break;
        }
        prep_commit_and_fetch(sqe, idx, entries_[idx].commit_id, reply_sz);
        int sr = io_uring_submit(&ring_);
        if (sr < 0) {
            ec_ = {-sr, std::system_category()};
            stop = true;
            break;
        }
    }

    // A worker that gave up can't serve its queues any more, and nothing
    // else tells run(). The kernel would wait for it forever.
    impl_.worker_exited();
}

void RingWorker::teardown() noexcept
{
    if (ring_inited_) {
        io_uring_queue_exit(&ring_);
        ring_inited_ = false;
    }
    for (auto& e : entries_) {
        if (e.buf) {
            ::munmap(e.buf, e.buf_len);
            e.buf = nullptr;
        }
    }
    entries_.clear();
}

}  // namespace fex::detail
