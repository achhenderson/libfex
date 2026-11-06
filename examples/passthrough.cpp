// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// passthrough.cpp - a fusex daemon that mirrors a backing directory.
//
// Usage:
//
//     passthrough <backing_dir> <mountpoint>
//
// This is the fusex equivalent of libfuse's example/passthrough_ll.c:
// for every fusex callback, we run the matching *at() syscall against
// an O_PATH fd of the backing directory.
//
// Inode model: we keep a map nodeid -> O_PATH fd. The root is always
// nodeid 1. Every successful LOOKUPX or MKOBJX mints a fresh nodeid
// (or re-uses one), stashes the fd, and bumps a per-inode `nlookup`
// counter. The kernel sends FUSE_FORGET / FUSE_BATCH_FORGET when the
// VFS dentry/inode cache evicts an entry; we decrement nlookup and
// drop the entry (closing the O_PATH fd) when it reaches zero. The
// root entry is pinned with nlookup=1 from construction and is never
// forgotten — its fd lives until the daemon exits.

#include <fex/fex.hpp>

#include "daemonize.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>     // std::getenv
#include <cstring>
#include <dirent.h>
#include <expected>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace {

// ---- debug tracing ----------------------------------------------------
//
// Set FEX_DEBUG=1 in the environment to log every callback invocation
// with its key arguments. When unset (the default), the trace helper
// compiles down to a single load-relaxed atomic test, so there is no
// per-callback formatting cost.
//
// Examples:
//   FEX_DEBUG=1 ./fex-passthrough /mnt/src /mnt/test
//
// The trace output goes to stderr so it doesn't mix with anything the
// daemon's filesystem callbacks might print on stdout.
const bool kFexDebug = [] {
    const char* e = std::getenv("FEX_DEBUG");
    return e && *e && *e != '0';
}();

template <class... A>
inline void trace(const char* fmt, A&&... args) {
    if (!kFexDebug)
        return;
    if constexpr (sizeof...(A) == 0)
        std::fputs(fmt, stderr);
    else
        std::fprintf(stderr, fmt, std::forward<A>(args)...);
}

// Helpers to keep trace() call sites short.
inline unsigned long long u64(fex::NodeId n) {
    return static_cast<unsigned long long>(fex::to_underlying(n));
}
inline unsigned long long u64(fex::FileHandle h) {
    return static_cast<unsigned long long>(fex::to_underlying(h));
}

// Wrap an errno-returning call so we yield std::unexpected on failure.
inline std::unexpected<fex::Errc> wrap_errno() {
    return std::unexpected{static_cast<fex::Errc>(errno)};
}

// std::errc has no portable name for ESTALE; cast directly.
inline std::unexpected<fex::Errc> stale() {
    return std::unexpected{static_cast<fex::Errc>(ESTALE)};
}

// Owned O_PATH fd. Same shape as fex::UniqueFd, but we keep them
// separate so the example also stands as a worked-from-scratch view.
class Fd {
public:
    Fd() noexcept = default;
    explicit Fd(int fd) noexcept : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(Fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) { reset(); fd_ = o.fd_; o.fd_ = -1; }
        return *this;
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }
    int release() noexcept { int r = fd_; fd_ = -1; return r; }
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0 && fd_ != fd) ::close(fd_);
        fd_ = fd;
    }
private:
    int fd_ = -1;
};

// Inode table -----------------------------------------------------------

struct Inode {
    Fd            path_fd;   // O_PATH fd to the backing object
    std::uint64_t nlookup;   // kernel-observed lookup count; FORGET decrements
};

class InodeTable {
public:
    explicit InodeTable(Fd root_fd) {
        // nodeid 1 == root. Pinned: we never let nlookup hit zero here.
        auto in = std::make_shared<Inode>();
        in->path_fd = std::move(root_fd);
        in->nlookup = 1;
        map_.emplace(fex::to_underlying(fex::NodeId::root), std::move(in));
    }

    std::shared_ptr<Inode> get(fex::NodeId n) const {
        std::shared_lock lk(mu_);
        auto it = map_.find(fex::to_underlying(n));
        return it == map_.end() ? nullptr : it->second;
    }

    // Insert a new inode and return its nodeid. We just use the inode
    // number from the backing stat as the nodeid - it's stable for the
    // life of the underlying filesystem and collisions across distinct
    // st_dev are unlikely for a single-backing-dir example.
    fex::NodeId insert(Fd fd, std::uint64_t st_ino) {
        std::unique_lock lk(mu_);
        auto [it, ins] = map_.try_emplace(st_ino);
        if (ins) {
            it->second = std::make_shared<Inode>();
            it->second->path_fd = std::move(fd);
        }
        // else: re-lookup; existing path_fd stays.
        ++it->second->nlookup;
        return static_cast<fex::NodeId>(st_ino);
    }

    // Decrement nlookup by `n`. If the counter reaches zero (and the
    // entry is not the pinned root), drop the entry from the map;
    // ~Fd() closes the O_PATH fd. Never let the root go.
    void forget(fex::NodeId nid, std::uint64_t n) noexcept {
        const auto key = fex::to_underlying(nid);
        if (key == fex::to_underlying(fex::NodeId::root))
            return;  // root is pinned
        std::unique_lock lk(mu_);
        forget_locked(key, n);
    }

    // Batch variant: take the write lock once, then iterate.
    void forget_many(
        std::span<const std::pair<fex::NodeId, std::uint64_t>> items
    ) noexcept {
        std::unique_lock lk(mu_);
        for (auto& [nid, n] : items) {
            const auto key = fex::to_underlying(nid);
            if (key == fex::to_underlying(fex::NodeId::root)) continue;
            forget_locked(key, n);
        }
    }

private:
    // Must be called with mu_ held in unique mode.
    void forget_locked(std::uint64_t key, std::uint64_t n) noexcept {
        auto it = map_.find(key);
        if (it == map_.end()) return;
        auto& nl = it->second->nlookup;
        // Saturate at zero so a misbehaving kernel can't underflow us.
        nl = (n >= nl) ? 0 : (nl - n);
        if (nl == 0) map_.erase(it);
    }

    mutable std::shared_mutex mu_;
    std::unordered_map<std::uint64_t, std::shared_ptr<Inode>> map_;
};

// Statx packing helpers -------------------------------------------------

void fill_statx(const struct ::stat& st, fex::StatxOut& out) {
    namespace m = fex::statx_mask;
    out.mask = m::type | m::mode | m::nlink | m::uid | m::gid
             | m::atime | m::mtime | m::ctime
             | m::ino | m::size | m::blocks;
    out.blksize    = static_cast<std::uint32_t>(st.st_blksize);
    out.nlink      = static_cast<std::uint32_t>(st.st_nlink);
    out.uid        = st.st_uid;
    out.gid        = st.st_gid;
    out.mode       = static_cast<std::uint16_t>(st.st_mode);
    out.ino        = st.st_ino;
    out.size       = static_cast<std::uint64_t>(st.st_size);
    out.blocks     = static_cast<std::uint64_t>(st.st_blocks);
    out.atime      = {st.st_atim.tv_sec, static_cast<std::uint32_t>(st.st_atim.tv_nsec)};
    out.mtime      = {st.st_mtim.tv_sec, static_cast<std::uint32_t>(st.st_mtim.tv_nsec)};
    out.ctime      = {st.st_ctim.tv_sec, static_cast<std::uint32_t>(st.st_ctim.tv_nsec)};
    out.rdev_major = major(st.st_rdev);
    out.rdev_minor = minor(st.st_rdev);
    out.dev_major  = major(st.st_dev);
    out.dev_minor  = minor(st.st_dev);
}

}  // anonymous

// =======================================================================
//                         PassthroughFs
// =======================================================================

class PassthroughFs final : public fex::Filesystem {
public:
    explicit PassthroughFs(Fd backing) : table_(std::move(backing)) {}

    std::expected<void, fex::Errc> init(fex::InitInfo& info) override {
        // Default flags from the dispatcher are fine, leave info.flags alone.
        // This one always prints because it's the boot-handshake heartbeat.
        std::fprintf(stderr,
            "fex passthrough: kernel %u.%u flags=0x%llx max_ra=%u\n",
            info.kernel_major, info.kernel_minor,
            (unsigned long long)info.kernel_flags, info.max_readahead);
        return {};
    }

    std::expected<fex::EntryOut, fex::Errc>
    lookup_root(const fex::Context&) override {
        trace("[fex] lookup_root\n");
        fex::EntryOut e;
        e.nodeid       = fex::NodeId::root;
        e.entry_valid  = std::chrono::seconds(1);
        e.negative     = false;
        return e;
    }

    std::expected<fex::EntryOut, fex::Errc>
    lookupx(const fex::Context&, fex::NodeId parent,
            std::string_view name) override
    {
        trace("[fex] lookupx parent=%llu name=%.*s\n",
              u64(parent), (int)name.size(), name.data());
        auto p = table_.get(parent);
        if (!p) return stale();

        // openat() with O_PATH gives us a leak-free reference to the
        // child without consuming any pollable fd resources.
        std::string nm{name};
        int fd = ::openat(p->path_fd.get(), nm.c_str(),
                          O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ENOENT) {
                // Cache the negative.
                fex::EntryOut e;
                e.negative = true;
                return e;
            }
            return wrap_errno();
        }
        Fd cfd(fd);

        struct ::stat st;
        if (::fstatat(cfd.get(), "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) < 0)
            return wrap_errno();

        fex::EntryOut e;
        e.nodeid      = table_.insert(std::move(cfd), st.st_ino);
        e.entry_valid = std::chrono::seconds(1);
        return e;
    }

    void forget(fex::NodeId n, std::uint64_t nlookup) noexcept override {
        trace("[fex] forget node=%llu n=%llu\n",
              u64(n), (unsigned long long)nlookup);
        table_.forget(n, nlookup);
    }

    void forget_multi(
        std::span<const std::pair<fex::NodeId, std::uint64_t>> items
    ) noexcept override {
        trace("[fex] batch_forget count=%zu\n", items.size());
        // Take the InodeTable write lock once for the whole batch
        // rather than once per entry as the default impl would.
        table_.forget_many(items);
    }

    std::expected<fex::StatxOut, fex::Errc>
    statx(const fex::Context&, fex::NodeId n) override {
        trace("[fex] statx node=%llu\n", u64(n));
        auto in = table_.get(n);
        if (!in) return stale();
        struct ::stat st;
        if (::fstatat(in->path_fd.get(), "", &st,
                      AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) < 0)
            return wrap_errno();
        fex::StatxOut out;
        fill_statx(st, out);
        return out;
    }

    std::expected<fex::StatxOut, fex::Errc>
    setstatx(const fex::Context&, fex::NodeId n, fex::FileHandle fh,
             const fex::SetStatxIn& in) override
    {
        trace("[fex] setstatx node=%llu fh=%llu mask=0x%x mode=0%o size=%llu\n",
              u64(n), u64(fh), (unsigned)in.mask, (unsigned)in.mode,
              (unsigned long long)in.size);

        // Prefer the open fd (ftruncate/fchmod/futimens directly). Fall
        // back to /proc/self/fd<N> for path-based calls when the caller
        // didn't open the file (chmod/utimensat from a path, or
        // truncate(2) without an fd).
        auto inode = table_.get(n);
        if (!inode) return stale();
        int fd = file_fd(fh);
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d",
                      inode->path_fd.get());

        if (in.mask & fex::statx_mask::mode) {
            int r = (fd >= 0) ? ::fchmod(fd, in.mode)
                              : ::chmod(proc, in.mode);
            if (r < 0) return wrap_errno();
        }
        if (in.mask & (fex::statx_mask::uid | fex::statx_mask::gid)) {
            uid_t u = (in.mask & fex::statx_mask::uid) ? in.uid : (uid_t)-1;
            gid_t g = (in.mask & fex::statx_mask::gid) ? in.gid : (gid_t)-1;
            // lchown() on the /proc link would change the link itself.
            int r = (fd >= 0) ? ::fchown(fd, u, g)
                              : ::fchownat(inode->path_fd.get(), "", u, g,
                                           AT_EMPTY_PATH);
            if (r < 0) return wrap_errno();
        }
        if (in.mask & fex::statx_mask::size) {
            int r = (fd >= 0) ? ::ftruncate(fd, (off_t)in.size)
                              : ::truncate(proc, (off_t)in.size);
            if (r < 0) return wrap_errno();
        }
        if (in.mask & (fex::statx_mask::atime | fex::statx_mask::mtime)) {
            struct timespec ts[2];
            ts[0] = (in.mask & fex::statx_mask::atime)
                    ? timespec{in.atime.sec, (long)in.atime.nsec}
                    : timespec{0, UTIME_OMIT};
            ts[1] = (in.mask & fex::statx_mask::mtime)
                    ? timespec{in.mtime.sec, (long)in.mtime.nsec}
                    : timespec{0, UTIME_OMIT};
            int r = (fd >= 0) ? ::futimens(fd, ts)
                              : ::utimensat(AT_FDCWD, proc, ts, 0);
            if (r < 0) return wrap_errno();
        }

        return statx(fex::Context{}, n);
    }

    std::expected<fex::EntryOut, fex::Errc>
    mkobjx(const fex::Context& ctx, fex::NodeId parent,
           const fex::MkobjxIn& mi) override
    {
        trace("[fex] mkobjx parent=%llu mode=0%o flags=0x%x name=%.*s\n",
              u64(parent), (unsigned)mi.stat.mode, (unsigned)mi.flags,
              (int)mi.name.size(), mi.name.data());
        auto p = table_.get(parent);
        if (!p) return stale();

        const std::uint16_t mode = mi.stat.mode;
        const auto kind = mode & S_IFMT;
        std::string nm{mi.name};

        if (mi.flags & fex::kMkobjxTmpfile) {
            // O_TMPFILE - create in parent dir.
            int fd = ::openat(p->path_fd.get(), ".",
                              O_TMPFILE | O_RDWR | O_CLOEXEC,
                              mode & 07777);
            if (fd < 0) return wrap_errno();
            // The kernel checks that the owner is the one it asked for.
            if (::fchown(fd, mi.stat.uid, mi.stat.gid) < 0 && errno != EPERM) {
                ::close(fd);
                return wrap_errno();
            }
            // chown clears setuid and setgid.
            if ((mode & (S_ISUID | S_ISGID)) && ::fchmod(fd, mode & 07777) < 0) {
                ::close(fd);
                return wrap_errno();
            }
            struct ::stat st;
            if (::fstat(fd, &st) < 0) { ::close(fd); return wrap_errno(); }
            // Re-open via /proc to get a stable O_PATH fd.
            char proc[64];
            std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
            int pfd = ::open(proc, O_PATH | O_CLOEXEC);
            ::close(fd);
            if (pfd < 0) return wrap_errno();
            fex::EntryOut e;
            e.nodeid      = table_.insert(Fd{pfd}, st.st_ino);
            e.entry_valid = std::chrono::seconds(1);
            return e;
        }

        int ret = -1;
        switch (kind) {
        case S_IFREG:
            ret = ::mknodat(p->path_fd.get(), nm.c_str(), mode, 0);
            break;
        case S_IFDIR:
            ret = ::mkdirat(p->path_fd.get(), nm.c_str(), mode & 07777);
            break;
        case S_IFLNK: {
            std::string tgt{mi.link_target};
            ret = ::symlinkat(tgt.c_str(), p->path_fd.get(), nm.c_str());
            break;
        }
        case S_IFCHR: case S_IFBLK: case S_IFIFO: case S_IFSOCK:
            ret = ::mknodat(p->path_fd.get(), nm.c_str(), mode,
                            makedev(mi.stat.rdev_major, mi.stat.rdev_minor));
            break;
        default:
            return std::unexpected{fex::Errc::invalid_argument};
        }
        if (ret < 0) return wrap_errno();

        // Set owner from the requested stat so the new object inherits
        // the requesting caller's uid/gid even if we're running as a
        // different user. The kernel checks the owner and mode of the new
        // inode against what it asked for and fails the create otherwise.
        if (::fchownat(p->path_fd.get(), nm.c_str(),
                       mi.stat.uid, mi.stat.gid,
                       AT_SYMLINK_NOFOLLOW) < 0) {
            // Non-fatal; ignore EPERM (unprivileged daemon).
            if (errno != EPERM) return wrap_errno();
        }
        // chown clears setuid and setgid.
        if (kind != S_IFLNK && (mode & (S_ISUID | S_ISGID)) &&
            ::fchmodat(p->path_fd.get(), nm.c_str(), mode & 07777, 0) < 0)
            return wrap_errno();
        (void)ctx;

        int cfd = ::openat(p->path_fd.get(), nm.c_str(),
                           O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (cfd < 0) return wrap_errno();
        struct ::stat st;
        if (::fstatat(cfd, "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) < 0) {
            ::close(cfd); return wrap_errno();
        }
        fex::EntryOut e;
        e.nodeid      = table_.insert(Fd{cfd}, st.st_ino);
        e.entry_valid = std::chrono::seconds(1);
        return e;
    }

    std::expected<void, fex::Errc>
    unlink(const fex::Context&, fex::NodeId parent,
           std::string_view name) override
    {
        trace("[fex] unlink parent=%llu name=%.*s\n",
              u64(parent), (int)name.size(), name.data());
        auto p = table_.get(parent);
        if (!p) return stale();
        std::string nm{name};
        if (::unlinkat(p->path_fd.get(), nm.c_str(), 0) < 0)
            return wrap_errno();
        return {};
    }

    std::expected<void, fex::Errc>
    rmdir(const fex::Context&, fex::NodeId parent,
          std::string_view name) override
    {
        trace("[fex] rmdir parent=%llu name=%.*s\n",
              u64(parent), (int)name.size(), name.data());
        auto p = table_.get(parent);
        if (!p) return stale();
        std::string nm{name};
        if (::unlinkat(p->path_fd.get(), nm.c_str(), AT_REMOVEDIR) < 0)
            return wrap_errno();
        return {};
    }

    std::expected<void, fex::Errc>
    rename(const fex::Context&, fex::NodeId od, std::string_view on,
           fex::NodeId nd, std::string_view nn, std::uint32_t flags) override
    {
        trace("[fex] rename %llu/%.*s -> %llu/%.*s flags=0x%x\n",
              u64(od), (int)on.size(), on.data(),
              u64(nd), (int)nn.size(), nn.data(), (unsigned)flags);
        auto o = table_.get(od);
        auto n = table_.get(nd);
        if (!o || !n) return stale();
        std::string os{on}, ns{nn};
        if (::renameat2(o->path_fd.get(), os.c_str(),
                        n->path_fd.get(), ns.c_str(), flags) < 0)
            return wrap_errno();
        return {};
    }

    std::expected<void, fex::Errc>
    link(const fex::Context&, fex::NodeId oldnodeid,
         fex::NodeId newparent, std::string_view newname) override
    {
        trace("[fex] link old=%llu newparent=%llu name=%.*s\n",
              u64(oldnodeid), u64(newparent),
              (int)newname.size(), newname.data());
        auto src = table_.get(oldnodeid);
        auto dst = table_.get(newparent);
        if (!src || !dst) return stale();
        std::string nm{newname};
        // linkat from an O_PATH fd needs AT_EMPTY_PATH.
        if (::linkat(src->path_fd.get(), "",
                     dst->path_fd.get(), nm.c_str(), AT_EMPTY_PATH) < 0)
            return wrap_errno();
        return {};
    }

    std::expected<std::string, fex::Errc>
    readlink(const fex::Context&, fex::NodeId n) override {
        trace("[fex] readlink node=%llu\n", u64(n));
        auto in = table_.get(n);
        if (!in) return stale();
        std::string s(4096, '\0');
        ssize_t r = ::readlinkat(in->path_fd.get(), "", s.data(), s.size());
        if (r < 0) return wrap_errno();
        s.resize(r);
        return s;
    }

    std::expected<std::size_t, fex::Errc>
    read(const fex::Context&, fex::NodeId n, fex::FileHandle fh,
         std::uint64_t off, std::span<std::byte> out) override
    {
        trace("[fex] read node=%llu fh=%llu off=%llu size=%zu\n",
              u64(n), u64(fh), (unsigned long long)off, out.size());
        auto io = io_fd(n, fh, O_RDONLY);
        if (!io) return std::unexpected{io.error()};
        ssize_t r = ::pread(io->fd, out.data(), out.size(), (off_t)off);
        if (r < 0) return wrap_errno();
        return static_cast<std::size_t>(r);
    }

    std::expected<std::size_t, fex::Errc>
    write(const fex::Context&, fex::NodeId n, fex::FileHandle fh,
          std::uint64_t off, std::span<const std::byte> in) override
    {
        trace("[fex] write node=%llu fh=%llu off=%llu size=%zu\n",
              u64(n), u64(fh), (unsigned long long)off, in.size());
        auto io = io_fd(n, fh, O_WRONLY);
        if (!io) return std::unexpected{io.error()};
        ssize_t r = ::pwrite(io->fd, in.data(), in.size(), (off_t)off);
        if (r < 0) return wrap_errno();
        return static_cast<std::size_t>(r);
    }

    std::expected<fex::StatfsOut, fex::Errc>
    statfs(const fex::Context&, fex::NodeId n) override {
        trace("[fex] statfs node=%llu\n", u64(n));
        auto in = table_.get(n);
        if (!in) return stale();
        struct ::statvfs sv;
        if (::fstatvfs(in->path_fd.get(), &sv) < 0) return wrap_errno();
        fex::StatfsOut out;
        out.blocks  = sv.f_blocks;
        out.bfree   = sv.f_bfree;
        out.bavail  = sv.f_bavail;
        out.files   = sv.f_files;
        out.ffree   = sv.f_ffree;
        out.bsize   = sv.f_bsize;
        out.namelen = sv.f_namemax;
        out.frsize  = sv.f_frsize;
        return out;
    }

    std::expected<void, fex::Errc>
    fallocate(const fex::Context&, fex::NodeId n, fex::FileHandle fh,
              std::uint32_t mode,
              std::uint64_t off, std::uint64_t len) override
    {
        trace("[fex] fallocate node=%llu fh=%llu mode=0x%x off=%llu len=%llu\n",
              u64(n), u64(fh), (unsigned)mode,
              (unsigned long long)off, (unsigned long long)len);
        auto io = io_fd(n, fh, O_WRONLY);
        if (!io) return std::unexpected{io.error()};
        int r = ::fallocate(io->fd, mode, (off_t)off, (off_t)len);
        if (r < 0) return wrap_errno();
        return {};
    }

    std::expected<void, fex::Errc>
    fsync(const fex::Context&, fex::NodeId n, fex::FileHandle fh, bool datasync) override
    {
        trace("[fex] fsync node=%llu fh=%llu datasync=%d\n", u64(n), u64(fh), datasync);
        auto io = io_fd(n, fh, O_RDONLY);
        if (!io) return std::unexpected{io.error()};
        int r = datasync ? ::fdatasync(io->fd) : ::fsync(io->fd);
        if (r < 0) return wrap_errno();
        return {};
    }

    std::expected<void, fex::Errc>
    syncfs(const fex::Context&) override {
        trace("[fex] syncfs\n");
        auto in = table_.get(fex::NodeId::root);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", in->path_fd.get());
        // syncfs() doesn't take the O_PATH fd.
        Fd fd{::open(proc, O_DIRECTORY | O_RDONLY | O_CLOEXEC)};
        if (fd.get() < 0) return wrap_errno();
        if (::syncfs(fd.get()) < 0) return wrap_errno();
        return {};
    }

    // File handle table -----------------------------------------------
    //
    // The backing path_fd we cache per inode is O_PATH, which can't do
    // I/O. open() upgrades it via /proc/self/fd/<N> to a real fd at the
    // requested access mode and stashes it under a new FileHandle.
    // read/write/fallocate find it via file_fd(fh).

    std::expected<fex::OpenOut, fex::Errc>
    open(const fex::Context&, fex::NodeId n, std::uint32_t flags) override {
        trace("[fex] open node=%llu flags=0x%x\n", u64(n), (unsigned)flags);
        auto inode = table_.get(n);
        if (!inode) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d",
                      inode->path_fd.get());
        // Mask to persistent open(2) flags; O_CREAT / O_TRUNC / O_EXCL
        // have already been consumed by the VFS by the time the
        // kernel forwards us here. O_CLOEXEC is ours.
        constexpr int kPersistent = O_ACCMODE | O_APPEND | O_NONBLOCK |
                                    O_DIRECT | O_NOATIME;
        int fd = ::open(proc, ((int)flags & kPersistent) | O_CLOEXEC);
        if (fd < 0) return wrap_errno();

        std::lock_guard lk(files_mu_);
        auto handle = static_cast<fex::FileHandle>(++file_id_);
        files_.emplace(fex::to_underlying(handle), Fd{fd});
        return fex::OpenOut{.fh = handle, .open_flags = 0};
    }

    std::expected<void, fex::Errc>
    release(const fex::Context&, fex::NodeId n, fex::FileHandle fh,
            std::uint32_t flags) override {
        trace("[fex] release node=%llu fh=%llu flags=0x%x\n",
              u64(n), u64(fh), (unsigned)flags);
        std::lock_guard lk(files_mu_);
        files_.erase(fex::to_underlying(fh));
        return {};
    }

    // Directory handle table -----------------------------------------

    std::expected<fex::OpenOut, fex::Errc>
    opendir(const fex::Context&, fex::NodeId n) override {
        trace("[fex] opendir node=%llu\n", u64(n));
        auto in = table_.get(n);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", in->path_fd.get());
        int fd = ::open(proc, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        if (fd < 0) return wrap_errno();
        DIR* d = ::fdopendir(fd);
        if (!d) { ::close(fd); return wrap_errno(); }
        std::lock_guard lk(dirs_mu_);
        auto fh = static_cast<fex::FileHandle>(++dir_id_);
        dirs_[fex::to_underlying(fh)] = d;
        return fex::OpenOut{.fh = fh, .open_flags = 0};
    }

    std::expected<void, fex::Errc>
    releasedir(const fex::Context&, fex::NodeId n, fex::FileHandle fh) override {
        trace("[fex] releasedir node=%llu fh=%llu\n", u64(n), u64(fh));
        (void)n;
        std::lock_guard lk(dirs_mu_);
        auto it = dirs_.find(fex::to_underlying(fh));
        if (it != dirs_.end()) {
            ::closedir(it->second);
            dirs_.erase(it);
        }
        return {};
    }

    std::expected<void, fex::Errc>
    fsyncdir(const fex::Context&, fex::NodeId n, fex::FileHandle fh, bool datasync) override
    {
        trace("[fex] fsyncdir node=%llu fh=%llu datasync=%d\n", u64(n), u64(fh), datasync);
        int fd;
        {
            std::lock_guard lk(dirs_mu_);
            auto it = dirs_.find(fex::to_underlying(fh));
            if (it == dirs_.end()) return std::unexpected{fex::Errc::bad_file_descriptor};
            fd = ::dirfd(it->second);
        }
        int r = datasync ? ::fdatasync(fd) : ::fsync(fd);
        if (r < 0) return wrap_errno();
        return {};
    }

    std::expected<void, fex::Errc>
    readdir(const fex::Context&, fex::NodeId n, fex::FileHandle fh,
            std::uint64_t off, fex::DirentWriter& out) override
    {
        trace("[fex] readdir node=%llu fh=%llu off=%llu\n",
              u64(n), u64(fh), (unsigned long long)off);
        (void)n;
        DIR* d;
        {
            std::lock_guard lk(dirs_mu_);
            auto it = dirs_.find(fex::to_underlying(fh));
            if (it == dirs_.end()) return std::unexpected{fex::Errc::bad_file_descriptor};
            d = it->second;
        }
        ::seekdir(d, off);
        while (true) {
            errno = 0;
            struct ::dirent* de = ::readdir(d);
            if (!de) {
                if (errno) return wrap_errno();
                return {};
            }
            std::uint64_t next = ::telldir(d);
            if (!out.add(de->d_name, de->d_ino, next, de->d_type)) {
                // Buffer full; rewind so the kernel sees us at the
                // entry we couldn't pack next time.
                ::seekdir(d, off);
                return {};
            }
            off = next;
        }
    }

    // xattrs are passthrough-only.
    std::expected<std::size_t, fex::Errc>
    getxattr(const fex::Context&, fex::NodeId n, std::string_view name,
             std::span<std::byte> out) override
    {
        trace("[fex] getxattr node=%llu name=%.*s size=%zu\n",
              u64(n), (int)name.size(), name.data(), out.size());
        auto in = table_.get(n);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", in->path_fd.get());
        std::string nm{name};
        // The /proc link must be followed to reach the object; the l*
        // variants would act on the link itself (EPERM for user.* names).
        ssize_t r = ::getxattr(proc, nm.c_str(), out.data(), out.size());
        if (r < 0) return wrap_errno();
        return static_cast<std::size_t>(r);
    }

    std::expected<void, fex::Errc>
    setxattr(const fex::Context&, fex::NodeId n, std::string_view name,
             std::span<const std::byte> value, std::uint32_t flags) override
    {
        trace("[fex] setxattr node=%llu name=%.*s vsize=%zu flags=0x%x\n",
              u64(n), (int)name.size(), name.data(),
              value.size(), (unsigned)flags);
        auto in = table_.get(n);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", in->path_fd.get());
        std::string nm{name};
        if (::setxattr(proc, nm.c_str(), value.data(), value.size(),
                       (int)flags) < 0)
            return wrap_errno();
        return {};
    }

    std::expected<std::size_t, fex::Errc>
    listxattr(const fex::Context&, fex::NodeId n,
              std::span<std::byte> out) override
    {
        trace("[fex] listxattr node=%llu size=%zu\n", u64(n), out.size());
        auto in = table_.get(n);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", in->path_fd.get());
        ssize_t r = ::listxattr(proc,
                                reinterpret_cast<char*>(out.data()),
                                out.size());
        if (r < 0) return wrap_errno();
        return static_cast<std::size_t>(r);
    }

    std::expected<void, fex::Errc>
    removexattr(const fex::Context&, fex::NodeId n,
                std::string_view name) override
    {
        trace("[fex] removexattr node=%llu name=%.*s\n",
              u64(n), (int)name.size(), name.data());
        auto in = table_.get(n);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", in->path_fd.get());
        std::string nm{name};
        if (::removexattr(proc, nm.c_str()) < 0) return wrap_errno();
        return {};
    }

private:
    // Look up the cached fd for an open regular file. Returns -1 if
    // `fh` is the zero sentinel, which is what the kernel sends for
    // regular files, or not in the table.
    int file_fd(fex::FileHandle fh) const {
        if (fex::to_underlying(fh) == 0) return -1;
        std::shared_lock lk(files_mu_);
        auto it = files_.find(fex::to_underlying(fh));
        return it == files_.end() ? -1 : it->second.get();
    }

    // Resolve `fh` to an fd usable at `mode`. If `fh` is live the
    // returned `owner` is empty and `fd` is borrowed from the files_
    // table. If `fh` is the zero sentinel, re-open the
    // inode's O_PATH fd via /proc/self/fd; `owner` keeps that fd alive
    // until the caller's scope ends.
    struct IoFd { int fd; Fd owner; };
    std::expected<IoFd, fex::Errc>
    io_fd(fex::NodeId n, fex::FileHandle fh, int mode) const {
        if (int fd = file_fd(fh); fd >= 0)
            return IoFd{fd, Fd{}};
        auto in = table_.get(n);
        if (!in) return stale();
        char proc[64];
        std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d",
                      in->path_fd.get());
        int t = ::open(proc, mode | O_CLOEXEC);
        if (t < 0) return wrap_errno();
        return IoFd{t, Fd{t}};
    }

    InodeTable table_;

    mutable std::shared_mutex files_mu_;
    std::unordered_map<std::uint64_t, Fd> files_;
    std::uint64_t file_id_ = 0;

    std::mutex dirs_mu_;
    std::unordered_map<std::uint64_t, DIR*> dirs_;
    std::uint64_t dir_id_ = 0;
};

namespace {

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s [-f|--foreground] [--source NAME] <backing_dir> <mountpoint>\n"
        "\n"
        "Mounts a fusex filesystem at <mountpoint> that mirrors the\n"
        "contents of <backing_dir>. Requires the fusex kernel module to\n"
        "be loaded.\n"
        "\n"
        "  -f, --foreground   stay in foreground (do not daemonize)\n"
        "  --source NAME      override the SOURCE field in /proc/mounts\n"
        "                     (default: realpath(<backing_dir>)). Lets a\n"
        "                     mount(8) helper preserve the device-arg the\n"
        "                     caller used, matching libfuse passthrough_ll.\n"
        "  -h, --help         this help\n"
        "\n"
        "Default is to fork into the background once the mount is live,\n"
        "so the command can be used from /etc/fstab or as a mount helper.\n",
        argv0);
}

}  // anonymous

// =======================================================================
//                                main
// =======================================================================

int main(int argc, char** argv)
{
    bool        foreground      = false;
    const char* source_override = nullptr;
    int  ai = 1;
    for (; ai < argc; ++ai) {
        std::string_view a = argv[ai];
        if (a == "-f" || a == "--foreground") {
            foreground = true;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else if (a == "--source") {
            if (ai + 1 >= argc) {
                std::fprintf(stderr, "--source requires an argument\n");
                return 2;
            }
            source_override = argv[++ai];
        } else if (a.substr(0, 9) == "--source=") {
            source_override = argv[ai] + 9;
        } else if (!a.empty() && a.front() == '-') {
            std::fprintf(stderr, "unknown option: %s\n", argv[ai]);
            usage(argv[0]);
            return 2;
        } else {
            break;
        }
    }
    if (argc - ai != 2) {
        usage(argv[0]);
        return 2;
    }
    const char* backing    = argv[ai];
    const char* mountpoint = argv[ai + 1];

    // The kernel already applied the caller's umask to the mode of a new
    // object and insists on that exact mode.
    ::umask(0);

    // One O_PATH fd per inode the kernel knows about.
    struct rlimit rl;
    if (::getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        (void)::setrlimit(RLIMIT_NOFILE, &rl);
    }

    int rfd = ::open(backing, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rfd < 0) {
        std::perror("open backing");
        return 1;
    }

    PassthroughFs fs(Fd{rfd});

    fex::SessionOptions opts;
    opts.mountpoint = mountpoint;
    opts.fsname     = "fex-passthrough";
    if (source_override) {
        opts.source = source_override;
    } else if (char* rp = ::realpath(backing, nullptr); rp) {
        opts.source = rp;
        ::free(rp);
    } else {
        opts.source = backing;
    }

    fex::Session session(std::move(opts));
    fex_example::install_signal_handlers(session);

    return fex_example::run_session(session, fs, mountpoint, foreground, "fex-passthrough");
}
