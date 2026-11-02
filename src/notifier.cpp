// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only

#include "notifier.hpp"
#include "session_impl.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <thread>
#include <utility>

#include <sys/uio.h>

namespace fex {

namespace detail {

struct Notifier::Msg {
    ::fuse_out_header              oh{};
    std::vector<std::byte>         payload;
    struct iovec                   iov[2]{};
    std::promise<std::error_code>  done;
};

std::error_code Notifier::start(int dev_fd)
{
    // FUSE_IO_URING_CMD_* needs SQE128, the kernel refuses it otherwise.
    io_uring_params params{};
    params.flags = IORING_SETUP_SQE128;
    int rc = io_uring_queue_init_params(4, &ring_, &params);
    if (rc < 0)
        return {-rc, std::system_category()};
    ring_inited_ = true;
    dev_fd_ = dev_fd;

    {
        std::lock_guard lk(mu_);
        running_ = true;
    }
    thread_ = std::thread([this] { run(); });
    return {};
}

std::future<std::error_code> Notifier::post(int code, std::vector<std::byte> payload)
{
    auto* m = new Msg;
    m->oh.len    = static_cast<std::uint32_t>(sizeof(m->oh) + payload.size());
    m->oh.error  = code;
    m->oh.unique = 0;
    m->payload   = std::move(payload);
    m->iov[0]    = {&m->oh, sizeof(m->oh)};
    m->iov[1]    = {m->payload.data(), m->payload.size()};
    auto fut = m->done.get_future();

    std::unique_lock lk(mu_);
    if (!running_ || stopping_) {
        lk.unlock();
        m->done.set_value({ENOTCONN, std::system_category()});
        delete m;
        return fut;
    }
    queue_.push_back(m);
    lk.unlock();
    cv_.notify_one();
    return fut;
}

// Returns false if the ring can't be used any more: the kernel can still be
// working on `m` and reads its buffers until it is done with it, so `m` stays
// allocated on purpose.
bool Notifier::deliver(Msg* m)
{
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe) {
        m->done.set_value({EAGAIN, std::system_category()});
        delete m;
        return true;
    }
    io_uring_prep_rw(IORING_OP_URING_CMD, sqe, dev_fd_, nullptr, 0, 0);
    sqe->cmd_op = FUSE_IO_URING_CMD_NOTIFY;
    sqe->addr   = reinterpret_cast<std::uint64_t>(&m->iov[0]);
    sqe->len    = 2;
    auto* cmd = reinterpret_cast<::fuse_uring_cmd_req*>(&sqe->cmd);
    std::memset(cmd, 0, sizeof(*cmd));
    io_uring_sqe_set_data(sqe, m);

    int rc;
    while ((rc = io_uring_submit(&ring_)) < 0) {
        if (rc != -EINTR && rc != -EAGAIN && rc != -EBUSY) {
            m->done.set_value({-rc, std::system_category()});
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    __kernel_timespec ts{.tv_sec = 1, .tv_nsec = 0};
    for (;;) {
        io_uring_cqe* cqe = nullptr;
        rc = io_uring_wait_cqe_timeout(&ring_, &cqe, &ts);
        if (rc == 0) {
            const bool ours = io_uring_cqe_get_data(cqe) == m;
            const int res = cqe->res;
            io_uring_cqe_seen(&ring_, cqe);
            if (!ours)
                continue;
            m->done.set_value(res < 0 ? std::error_code{-res, std::system_category()}
                                      : std::error_code{});
            delete m;
            return true;
        }
        if (rc == -ETIME) {
            std::lock_guard lk(mu_);
            if (stopping_ && std::chrono::steady_clock::now() >= deadline_) {
                m->done.set_value({ECANCELED, std::system_category()});
                return false;
            }
        } else if (rc != -EINTR) {
            m->done.set_value({-rc, std::system_category()});
            return false;
        }
    }
}

void Notifier::run()
{
    for (;;) {
        Msg* m;
        {
            std::unique_lock lk(mu_);
            cv_.wait(lk, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_) {
                finished_ = true;
                finished_cv_.notify_all();
                return;
            }
            m = queue_.front();
            queue_.pop_front();
        }
        if (!deliver(m)) {
            std::deque<Msg*> left;
            std::unique_lock lk(mu_);
            stopping_ = abandoned_ = finished_ = true;
            left.swap(queue_);
            finished_cv_.notify_all();
            lk.unlock();
            for (Msg* q : left) {
                q->done.set_value({ENOTCONN, std::system_category()});
                delete q;
            }
            return;
        }
    }
}

void Notifier::stop() noexcept
{
    std::deque<Msg*> left;
    {
        std::lock_guard lk(mu_);
        if (!stopping_) {
            stopping_ = true;
            deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        }
        left.swap(queue_);
    }
    cv_.notify_all();
    for (Msg* m : left) {
        m->done.set_value({ENOTCONN, std::system_category()});
        delete m;
    }
    if (!thread_.joinable())
        return;

    bool abandoned;
    {
        std::unique_lock lk(mu_);
        finished_cv_.wait(lk, [this] { return finished_; });
        abandoned = abandoned_;
    }
    // Leaving a thread with a command in flight waits for that command. That
    // thread doesn't touch this object any more, the ring is left to it.
    if (abandoned) {
        thread_.detach();
        return;
    }
    thread_.join();
    if (ring_inited_) {
        io_uring_queue_exit(&ring_);
        ring_inited_ = false;
    }
}

}  // namespace detail

// -----------------------------------------------------------------------
// Session::notify_*()
// -----------------------------------------------------------------------

namespace {

template <typename T>
void append(std::vector<std::byte>& v, const T& pod)
{
    const auto* p = reinterpret_cast<const std::byte*>(&pod);
    v.insert(v.end(), p, p + sizeof(pod));
}

void append_name(std::vector<std::byte>& v, std::string_view name)
{
    const auto* p = reinterpret_cast<const std::byte*>(name.data());
    v.insert(v.end(), p, p + name.size());
    v.push_back(std::byte{0});
}

std::future<std::error_code> ready_error(int err)
{
    std::promise<std::error_code> p;
    p.set_value({err, std::system_category()});
    return p.get_future();
}

}  // anonymous

std::future<std::error_code>
Session::notify_inval_inode(NodeId nodeid, std::int64_t offset, std::int64_t length)
{
    ::fuse_notify_inval_inode_out out{};
    out.ino = to_underlying(nodeid);
    out.off = offset;
    out.len = length;

    std::vector<std::byte> v;
    append(v, out);
    return impl_->notifier->post(FUSE_NOTIFY_INVAL_INODE, std::move(v));
}

std::future<std::error_code>
Session::notify_inval_entry(NodeId parent, std::string_view name)
{
    ::fuse_notify_inval_entry_out out{};
    out.parent  = to_underlying(parent);
    out.namelen = static_cast<std::uint32_t>(name.size());

    std::vector<std::byte> v;
    append(v, out);
    append_name(v, name);
    return impl_->notifier->post(FUSE_NOTIFY_INVAL_ENTRY, std::move(v));
}

std::future<std::error_code>
Session::notify_delete(NodeId parent, NodeId child, std::string_view name)
{
    ::fuse_notify_delete_out out{};
    out.parent  = to_underlying(parent);
    out.child   = to_underlying(child);
    out.namelen = static_cast<std::uint32_t>(name.size());

    std::vector<std::byte> v;
    append(v, out);
    append_name(v, name);
    return impl_->notifier->post(FUSE_NOTIFY_DELETE, std::move(v));
}

std::future<std::error_code>
Session::notify_store(NodeId nodeid, std::uint64_t offset, std::span<const std::byte> data)
{
    if (data.size() > std::numeric_limits<std::uint32_t>::max())
        return ready_error(EINVAL);

    ::fuse_notify_store_out out{};
    out.nodeid = to_underlying(nodeid);
    out.offset = offset;
    out.size   = static_cast<std::uint32_t>(data.size());

    std::vector<std::byte> v;
    v.reserve(sizeof(out) + data.size());
    append(v, out);
    v.insert(v.end(), data.begin(), data.end());
    return impl_->notifier->post(FUSE_NOTIFY_STORE, std::move(v));
}

std::future<std::error_code>
Session::notify_retrieve(NodeId nodeid, std::uint64_t offset, std::uint32_t size,
                         std::uint64_t cookie)
{
    if (cookie >= kRetrieveUnique >> 1)
        return ready_error(EINVAL);

    ::fuse_notify_retrieve_out out{};
    out.notify_unique = kRetrieveUnique | (cookie << 1);
    out.nodeid = to_underlying(nodeid);
    out.offset = offset;
    out.size   = size;

    std::vector<std::byte> v;
    append(v, out);
    return impl_->notifier->post(FUSE_NOTIFY_RETRIEVE, std::move(v));
}

std::future<std::error_code>
Session::notify_prune(std::span<const NodeId> nodeids)
{
    if (nodeids.size() > std::numeric_limits<std::uint32_t>::max())
        return ready_error(EINVAL);

    ::fuse_notify_prune_out out{};
    out.count = static_cast<std::uint32_t>(nodeids.size());

    std::vector<std::byte> v;
    v.reserve(sizeof(out) + nodeids.size() * sizeof(std::uint64_t));
    append(v, out);
    for (NodeId n : nodeids)
        append(v, to_underlying(n));
    return impl_->notifier->post(FUSE_NOTIFY_PRUNE, std::move(v));
}

}  // namespace fex
