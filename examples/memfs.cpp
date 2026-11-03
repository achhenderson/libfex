// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// memfs.cpp - a fusex daemon that keeps everything in memory.
//
// Usage:
//
//     fex-memfs [-f] [-o option[,option...]] <mountpoint>
//
// The fusex counterpart of libfuse's example/memfs_ll.cc. Nothing is left when
// the daemon ends.
//
// Data: a regular file's data lives in a memfd, which makes it sparse and
// swappable and leaves the concurrency of reads and writes to the kernel. That
// takes one file descriptor per regular file.
//
// Inode lifetime: `nlookup` counts what the kernel has been told minus what it
// has forgotten, `nlink` counts the names. An inode goes when both are zero:
// fusex doesn't open regular files on the daemon, so an unlinked file in use is
// simply one the kernel hasn't forgotten yet.
//
// Locking: ns_mu_ protects the namespace, which is the inode table, the
// directories and `parent`. Inode::attr_mu protects the attributes and xattrs,
// and is taken inside ns_mu_. A last reference can close a memfd full of data:
// that is done after dropping ns_mu_, which is why the InodePtrs of the
// operations that remove something are declared before the lock.

#include <fex/fex.hpp>

#include "daemonize.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <expected>
#include <fcntl.h>
#include <functional>
#include <linux/falloc.h>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/xattr.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

constexpr std::uint32_t kBlockSize = 4096;
constexpr std::size_t   kNameMax   = 255;

struct Config {
    // Bypass the data store so that the interface itself is measured.
    bool     null_io = false;
    bool     debug_io = false;
    // Invalidations at random files, as peer nodes changing them would cause.
    bool     notify_inval = false;
    unsigned notify_interval_ms = 1000;
    unsigned notify_storm = 64;
    // 0 means what the kernel allows, see max_write_ceiling().
    unsigned max_write = 0;
    unsigned threads = 0;
    unsigned queue_depth = 32;
};
Config g_cfg;

// What reads return under null_io, filled once at startup.
constexpr std::size_t kNullBufSize = 1u << 20;
std::vector<std::byte> g_null_buf;

// So that the reads of a null_io write aren't optimized away.
volatile unsigned char g_null_sink;

const auto g_start_time = std::chrono::steady_clock::now();

void log_io(const char* op, fex::NodeId n, std::uint64_t off, std::size_t size) {
    if (!g_cfg.debug_io)
        return;
    const std::chrono::duration<double> t = std::chrono::steady_clock::now() - g_start_time;
    std::fprintf(stderr, "[%10.3f] memfs %-5s ino=%llu off=%llu size=%zu end=%llu\n",
                 t.count(), op, (unsigned long long)fex::to_underlying(n),
                 (unsigned long long)off, size, (unsigned long long)(off + size));
}

[[noreturn]] void panic(const char* message) {
    std::fprintf(stderr, "MEMFS PANIC: %s\n", message);
    std::abort();
}

std::unexpected<fex::Errc> error(int e) {
    return std::unexpected{static_cast<fex::Errc>(e)};
}

std::unexpected<fex::Errc> last_error() {
    return error(errno);
}

fex::NodeId to_node(std::uint64_t id) {
    return static_cast<fex::NodeId>(id);
}

fex::Timespec now() {
    struct timespec ts;
    ::clock_gettime(CLOCK_REALTIME, &ts);
    return {ts.tv_sec, static_cast<std::uint32_t>(ts.tv_nsec)};
}

class Inode;
using InodePtr = std::shared_ptr<Inode>;

struct Dentry {
    InodePtr      inode;
    std::uint64_t cookie;   // its position in readdir
};

class Inode {
public:
    using Children = std::unordered_map<std::string, Dentry>;

    Inode(std::uint64_t ino, std::uint16_t full_mode, std::uint32_t owner, std::uint32_t group,
          std::uint32_t major, std::uint32_t minor, std::string link, int memfd)
        : id(ino), type(full_mode & S_IFMT), fd(memfd), rdev_major(major), rdev_minor(minor),
          target(std::move(link)), mode_(full_mode), uid_(owner), gid_(group)
    {
        atime_ = mtime_ = ctime_ = btime_ = now();
    }

    ~Inode() {
        if (fd >= 0)
            ::close(fd);
    }

    Inode(const Inode&)            = delete;
    Inode& operator=(const Inode&) = delete;

    bool is_dir() const { return S_ISDIR(type); }
    bool is_reg() const { return S_ISREG(type); }

    fex::StatxOut stat() {
        fex::StatxOut out;
        out.mask       = fex::statx_mask::basic | fex::statx_mask::btime;
        out.blksize    = kBlockSize;
        out.ino        = id;
        out.nlink      = nlink.load(std::memory_order_relaxed);
        out.rdev_major = rdev_major;
        out.rdev_minor = rdev_minor;
        if (fd >= 0) {
            struct ::stat st;
            if (::fstat(fd, &st) == 0) {
                out.size   = static_cast<std::uint64_t>(st.st_size);
                out.blocks = static_cast<std::uint64_t>(st.st_blocks);
            }
        } else if (is_reg()) {
            out.size   = null_size.load(std::memory_order_relaxed);
            out.blocks = (out.size + 511) / 512;
        } else if (S_ISLNK(type)) {
            out.size = target.size();
        } else if (is_dir()) {
            out.size = kBlockSize;
        }

        std::lock_guard lk(attr_mu);
        out.mode  = mode_;
        out.uid   = uid_;
        out.gid   = gid_;
        out.atime = atime_;
        out.btime = btime_;
        out.ctime = ctime_;
        out.mtime = mtime_;
        return out;
    }

    void apply(const fex::SetStatxIn& in) {
        namespace m = fex::statx_mask;
        const fex::Timespec t = now();
        std::lock_guard lk(attr_mu);
        if (in.mask & m::mode)
            mode_ = static_cast<std::uint16_t>(type | (in.mode & 07777));
        if (in.mask & m::uid)
            uid_ = in.uid;
        if (in.mask & m::gid)
            gid_ = in.gid;
        if (in.mask & m::atime)
            atime_ = in.atime;
        // The kernel sends these when it knows them, not on every change.
        if (in.mask & m::mtime)
            mtime_ = in.mtime;
        else if (in.mask & m::size)
            mtime_ = t;
        ctime_ = (in.mask & m::ctime) ? in.ctime : t;
    }

    void touch_atime() {
        const fex::Timespec t = now();
        std::lock_guard lk(attr_mu);
        atime_ = t;
    }

    // The data or the entries changed.
    void touch_modified() {
        const fex::Timespec t = now();
        std::lock_guard lk(attr_mu);
        mtime_ = ctime_ = t;
    }

    // Only the attributes changed.
    void touch_changed() {
        const fex::Timespec t = now();
        std::lock_guard lk(attr_mu);
        ctime_ = t;
    }

    std::expected<std::size_t, fex::Errc>
    getxattr(std::string_view name, std::span<std::byte> out) {
        std::lock_guard lk(attr_mu);
        const auto it = xattrs_.find(std::string{name});
        if (it == xattrs_.end())
            return error(ENODATA);
        const std::string& value = it->second;
        if (out.empty())
            return value.size();
        if (value.size() > out.size())
            return error(ERANGE);
        std::memcpy(out.data(), value.data(), value.size());
        return value.size();
    }

    std::expected<void, fex::Errc>
    setxattr(std::string_view name, std::span<const std::byte> value, std::uint32_t flags) {
        std::string key{name};
        std::string val{reinterpret_cast<const char*>(value.data()), value.size()};
        {
            std::lock_guard lk(attr_mu);
            const auto it = xattrs_.find(key);
            if (it != xattrs_.end()) {
                if (flags & XATTR_CREATE)
                    return error(EEXIST);
                it->second = std::move(val);
            } else {
                if (flags & XATTR_REPLACE)
                    return error(ENODATA);
                xattrs_.emplace(std::move(key), std::move(val));
            }
        }
        touch_changed();
        return {};
    }

    std::expected<std::size_t, fex::Errc> listxattr(std::span<std::byte> out) {
        std::lock_guard lk(attr_mu);
        std::size_t size = 0;
        for (const auto& [name, value] : xattrs_)
            size += name.size() + 1;
        if (out.empty())
            return size;
        if (size > out.size())
            return error(ERANGE);
        std::size_t pos = 0;
        for (const auto& [name, value] : xattrs_) {
            // The NUL of the string is the separator.
            std::memcpy(out.data() + pos, name.c_str(), name.size() + 1);
            pos += name.size() + 1;
        }
        return size;
    }

    std::expected<void, fex::Errc> removexattr(std::string_view name) {
        {
            std::lock_guard lk(attr_mu);
            if (xattrs_.erase(std::string{name}) == 0)
                return error(ENODATA);
        }
        touch_changed();
        return {};
    }

    void add_child(std::string name, InodePtr child) {
        const std::uint64_t cookie = next_cookie_++;
        auto it = children.emplace(std::move(name), Dentry{std::move(child), cookie}).first;
        by_cookie.emplace(cookie, &*it);
    }

    void remove_child(Children::iterator it) {
        by_cookie.erase(it->second.cookie);
        children.erase(it);
    }

    const std::uint64_t id;
    const std::uint16_t type;
    const int           fd;     // the memfd of a regular file, -1 otherwise and under null_io
    const std::uint32_t rdev_major, rdev_minor;
    const std::string   target; // of a symlink

    std::atomic<std::uint64_t> nlookup{0};
    std::atomic<std::uint32_t> nlink{0};

    // Under null_io: the size a regular file would have.
    std::atomic<std::uint64_t> null_size{0};

    // Under ns_mu_. Cookies only grow and are never reused, so a readdir going
    // on while entries come and go neither repeats nor skips what stays.
    Children children;
    std::map<std::uint64_t, Children::value_type*> by_cookie;
    std::uint64_t parent = 0;

private:
    // Cookies 1 and 2 are "." and "..".
    std::uint64_t next_cookie_ = 3;

    std::mutex    attr_mu;
    std::uint16_t mode_;
    std::uint32_t uid_, gid_;
    fex::Timespec atime_, mtime_, ctime_, btime_;
    std::map<std::string, std::string> xattrs_;
};

class MemFs final : public fex::Filesystem {
public:
    // Called from init(), with the mount coming up in this process.
    std::function<void()> on_init;

    MemFs() {
        auto root = std::make_shared<Inode>(fex::to_underlying(fex::NodeId::root),
                                            S_IFDIR | 0755, ::getuid(), ::getgid(),
                                            0, 0, std::string{}, -1);
        root->parent = root->id;
        root->nlink = 2;
        // The kernel has it from the mount on, and never forgets it in time.
        root->nlookup = 1;
        inodes_.emplace(root->id, std::move(root));
    }

    // What the invalidations pick from: the regular files the kernel knows.
    std::vector<std::uint64_t> known_files() {
        std::vector<std::uint64_t> ids;
        std::shared_lock lk(ns_mu_);
        for (const auto& [ino, in] : inodes_) {
            if (in->is_reg() && in->nlookup.load(std::memory_order_relaxed))
                ids.push_back(ino);
        }
        return ids;
    }

    std::expected<void, fex::Errc> init(fex::InitInfo& info) override {
        info.max_write = g_cfg.max_write;
        info.max_pages = static_cast<std::uint16_t>(
            std::min(g_cfg.max_write / kBlockSize, 65535u));
        if (on_init)
            on_init();
        return {};
    }

    std::expected<fex::EntryOut, fex::Errc> lookup_root(const fex::Context&) override {
        return entry(fex::to_underlying(fex::NodeId::root));
    }

    std::expected<fex::EntryOut, fex::Errc>
    lookupx(const fex::Context&, fex::NodeId parent, std::string_view name) override {
        if (name.size() > kNameMax)
            return error(ENAMETOOLONG);

        std::shared_lock lk(ns_mu_);
        const InodePtr dir = find(parent);
        if (!dir)
            return error(ESTALE);
        if (!dir->is_dir())
            return error(ENOTDIR);

        const auto it = dir->children.find(std::string{name});
        if (it == dir->children.end()) {
            fex::EntryOut negative;
            negative.negative = true;
            return negative;
        }
        const InodePtr& child = it->second.inode;
        child->nlookup.fetch_add(1, std::memory_order_relaxed);
        return entry(child->id);
    }

    void forget(fex::NodeId n, std::uint64_t nlookup) noexcept override {
        InodePtr last;
        std::unique_lock lk(ns_mu_);
        const auto it = inodes_.find(fex::to_underlying(n));
        if (it == inodes_.end())
            panic("FORGET of an inode that doesn't exist");
        const std::uint64_t had = it->second->nlookup.fetch_sub(nlookup, std::memory_order_relaxed);
        if (had < nlookup)
            panic("FORGET of more lookups than there were");
        if (had == nlookup && it->second->nlink.load(std::memory_order_relaxed) == 0) {
            last = std::move(it->second);
            inodes_.erase(it);
        }
    }

    std::expected<fex::StatxOut, fex::Errc>
    statx(const fex::Context&, fex::NodeId n) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        return in->stat();
    }

    std::expected<fex::StatxOut, fex::Errc>
    setstatx(const fex::Context&, fex::NodeId n, fex::FileHandle,
             const fex::SetStatxIn& attrs) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);

        if (attrs.mask & fex::statx_mask::size) {
            if (!in->is_reg())
                return error(EINVAL);
            if (g_cfg.null_io)
                in->null_size = attrs.size;
            else if (::ftruncate(in->fd, static_cast<off_t>(attrs.size)) < 0)
                return last_error();
        }
        in->apply(attrs);
        return in->stat();
    }

    std::expected<fex::EntryOut, fex::Errc>
    mkobjx(const fex::Context&, fex::NodeId parent, const fex::MkobjxIn& in) override {
        if (in.name.size() > kNameMax)
            return error(ENAMETOOLONG);

        auto made = new_inode(in.stat.mode, in.stat.uid, in.stat.gid, in.stat.rdev_major,
                              in.stat.rdev_minor, std::string{in.link_target});
        if (!made)
            return std::unexpected{made.error()};
        const InodePtr child = *made;
        const bool tmpfile = in.flags & fex::kMkobjxTmpfile;
        child->nlookup = 1;
        child->nlink = tmpfile ? 0 : (child->is_dir() ? 2 : 1);

        std::unique_lock lk(ns_mu_);
        const InodePtr dir = find(parent);
        if (!dir)
            return error(ESTALE);
        if (!dir->is_dir())
            return error(ENOTDIR);

        if (!tmpfile) {
            // Removed while a process still has it as its working directory.
            if (dir->nlink.load(std::memory_order_relaxed) == 0)
                return error(ENOENT);
            std::string name{in.name};
            if (dir->children.contains(name))
                return error(EEXIST);
            child->parent = dir->id;
            dir->add_child(std::move(name), child);
            if (child->is_dir())
                dir->nlink.fetch_add(1, std::memory_order_relaxed);
            dir->touch_modified();
        }
        inodes_.emplace(child->id, child);
        return entry(child->id);
    }

    std::expected<void, fex::Errc>
    unlink(const fex::Context&, fex::NodeId parent, std::string_view name) override {
        return remove(parent, name, false);
    }

    std::expected<void, fex::Errc>
    rmdir(const fex::Context&, fex::NodeId parent, std::string_view name) override {
        return remove(parent, name, true);
    }

    std::expected<void, fex::Errc>
    rename(const fex::Context&, fex::NodeId olddir, std::string_view oldname,
           fex::NodeId newdir, std::string_view newname, std::uint32_t flags) override {
        if (flags & ~static_cast<std::uint32_t>(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
            return error(EINVAL);
        if (newname.size() > kNameMax)
            return error(ENAMETOOLONG);

        InodePtr whiteout;
        if (flags & RENAME_WHITEOUT) {
            auto made = new_inode(S_IFCHR | 0600, ::getuid(), ::getgid(), 0, 0, std::string{});
            if (!made)
                return std::unexpected{made.error()};
            whiteout = *made;
            whiteout->nlink = 1;
        }

        InodePtr src, dst;
        std::unique_lock lk(ns_mu_);
        const InodePtr from = find(olddir), to = find(newdir);
        if (!from || !to)
            return error(ESTALE);
        if (!from->is_dir() || !to->is_dir())
            return error(ENOTDIR);

        std::string oldkey{oldname}, newkey{newname};
        const auto sit = from->children.find(oldkey);
        if (sit == from->children.end())
            return error(ENOENT);
        const auto dit = to->children.find(newkey);
        const bool exists = dit != to->children.end();
        src = sit->second.inode;
        if (exists)
            dst = dit->second.inode;

        if ((flags & RENAME_NOREPLACE) && exists)
            return error(EEXIST);

        if (flags & RENAME_EXCHANGE) {
            if (!exists)
                return error(ENOENT);
            // Both names stay, and with them their place in readdir.
            sit->second.inode.swap(dit->second.inode);
            move_dir(*src, *from, *to);
            move_dir(*dst, *to, *from);
        } else {
            // Two names of one object: POSIX says this does nothing.
            if (src == dst)
                return {};
            if (dst) {
                if (src->is_dir() != dst->is_dir())
                    return error(dst->is_dir() ? EISDIR : ENOTDIR);
                if (dst->is_dir() && !dst->children.empty())
                    return error(ENOTEMPTY);
                to->remove_child(dit);
                drop_link(*to, *dst);
            }
            from->remove_child(sit);
            to->add_child(std::move(newkey), src);
            move_dir(*src, *from, *to);
            if (whiteout) {
                from->add_child(std::move(oldkey), whiteout);
                inodes_.emplace(whiteout->id, whiteout);
            }
        }

        from->touch_modified();
        if (to != from)
            to->touch_modified();
        src->touch_changed();
        if (dst)
            dst->touch_changed();
        return {};
    }

    // The kernel doesn't count this as a lookup.
    std::expected<void, fex::Errc>
    link(const fex::Context&, fex::NodeId oldnodeid, fex::NodeId newparent,
         std::string_view newname) override {
        if (newname.size() > kNameMax)
            return error(ENAMETOOLONG);

        std::unique_lock lk(ns_mu_);
        const InodePtr in = find(oldnodeid), dir = find(newparent);
        if (!in || !dir)
            return error(ESTALE);
        if (in->is_dir())
            return error(EPERM);
        if (!dir->is_dir())
            return error(ENOTDIR);
        std::string name{newname};
        if (dir->children.contains(name))
            return error(EEXIST);

        dir->add_child(std::move(name), in);
        in->nlink.fetch_add(1, std::memory_order_relaxed);
        in->touch_changed();
        dir->touch_modified();
        return {};
    }

    std::expected<std::string, fex::Errc>
    readlink(const fex::Context&, fex::NodeId n) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        if (!S_ISLNK(in->type))
            return error(EINVAL);
        return in->target;
    }

    std::expected<std::size_t, fex::Errc>
    read(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
         std::span<std::byte> out) override {
        log_io("READ", n, off, out.size());
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        if (!in->is_reg())
            return error(EISDIR);

        std::size_t done;
        if (g_cfg.null_io) {
            done = null_read(*in, off, out);
        } else {
            const ssize_t r = ::pread(in->fd, out.data(), out.size(), static_cast<off_t>(off));
            if (r < 0)
                return last_error();
            done = static_cast<std::size_t>(r);
        }
        in->touch_atime();
        return done;
    }

    std::expected<std::size_t, fex::Errc>
    write(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
          std::span<const std::byte> data) override {
        log_io("WRITE", n, off, data.size());
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        if (!in->is_reg())
            return error(EISDIR);

        std::size_t done;
        if (g_cfg.null_io) {
            done = null_write(*in, off, data);
        } else {
            const ssize_t r = ::pwrite(in->fd, data.data(), data.size(), static_cast<off_t>(off));
            if (r < 0)
                return last_error();
            done = static_cast<std::size_t>(r);
        }
        in->touch_modified();
        return done;
    }

    std::expected<void, fex::Errc>
    fallocate(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint32_t mode,
              std::uint64_t off, std::uint64_t len) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        if (!in->is_reg())
            return error(ENODEV);

        if (g_cfg.null_io) {
            if (!(mode & FALLOC_FL_KEEP_SIZE))
                grow_null_size(*in, off + len);
        } else {
            const auto start = static_cast<off_t>(off), length = static_cast<off_t>(len);
            const int keep = static_cast<int>(mode & FALLOC_FL_KEEP_SIZE);
            int r;
            if (mode & FALLOC_FL_ZERO_RANGE) {
                // shmem has no such mode: a hole, then allocated again.
                r = ::fallocate(in->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, start, length);
                if (r == 0)
                    r = ::fallocate(in->fd, keep, start, length);
            } else {
                r = ::fallocate(in->fd, static_cast<int>(mode), start, length);
            }
            if (r < 0)
                return last_error();
        }
        in->touch_modified();
        return {};
    }

    // Memory is as durable as this gets.
    std::expected<void, fex::Errc>
    fsync(const fex::Context&, fex::NodeId, fex::FileHandle, bool) override {
        return {};
    }

    std::expected<void, fex::Errc>
    fsyncdir(const fex::Context&, fex::NodeId, fex::FileHandle, bool) override {
        return {};
    }

    std::expected<void, fex::Errc> syncfs(const fex::Context&) override {
        return {};
    }

    std::expected<fex::StatfsOut, fex::Errc>
    statfs(const fex::Context&, fex::NodeId) override {
        struct sysinfo si{};
        if (::sysinfo(&si) < 0)
            return last_error();
        const std::uint64_t unit = si.mem_unit ? si.mem_unit : 1;

        fex::StatfsOut out;
        out.bsize   = kBlockSize;
        out.frsize  = kBlockSize;
        out.namelen = kNameMax;
        out.blocks  = si.totalram * unit / kBlockSize;
        out.bfree   = si.freeram * unit / kBlockSize;
        out.bavail  = out.bfree;

        // A regular file takes a file descriptor.
        struct rlimit rl{};
        (void)::getrlimit(RLIMIT_NOFILE, &rl);
        std::shared_lock lk(ns_mu_);
        out.files = rl.rlim_cur;
        out.ffree = out.files - std::min<std::uint64_t>(out.files, inodes_.size());
        return out;
    }

    std::expected<void, fex::Errc>
    readdir(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
            fex::DirentWriter& out) override {
        InodePtr dir;
        {
            std::shared_lock lk(ns_mu_);
            dir = find(n);
            if (!dir)
                return error(ESTALE);
            if (!dir->is_dir())
                return error(ENOTDIR);

            bool room = true;
            if (off < 1)
                room = out.add(".", dir->id, 1, DT_DIR);
            if (room && off < 2)
                room = out.add("..", dir->parent, 2, DT_DIR);
            if (room) {
                for (auto it = dir->by_cookie.upper_bound(off); it != dir->by_cookie.end(); ++it) {
                    const auto& [name, de] = *it->second;
                    if (!out.add(name, de.inode->id, it->first, IFTODT(de.inode->type)))
                        break;
                }
            }
        }
        dir->touch_atime();
        return {};
    }

    std::expected<std::size_t, fex::Errc>
    getxattr(const fex::Context&, fex::NodeId n, std::string_view name,
             std::span<std::byte> out) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        return in->getxattr(name, out);
    }

    std::expected<void, fex::Errc>
    setxattr(const fex::Context&, fex::NodeId n, std::string_view name,
             std::span<const std::byte> value, std::uint32_t flags) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        return in->setxattr(name, value, flags);
    }

    std::expected<std::size_t, fex::Errc>
    listxattr(const fex::Context&, fex::NodeId n, std::span<std::byte> out) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        return in->listxattr(out);
    }

    std::expected<void, fex::Errc>
    removexattr(const fex::Context&, fex::NodeId n, std::string_view name) override {
        const InodePtr in = get(n);
        if (!in)
            return error(ESTALE);
        return in->removexattr(name);
    }

private:
    static fex::EntryOut entry(std::uint64_t id) {
        fex::EntryOut e;
        e.nodeid = to_node(id);
        return e;
    }

    // Under ns_mu_.
    InodePtr find(fex::NodeId n) const {
        const auto it = inodes_.find(fex::to_underlying(n));
        return it == inodes_.end() ? nullptr : it->second;
    }

    InodePtr get(fex::NodeId n) {
        std::shared_lock lk(ns_mu_);
        return find(n);
    }

    // Not under ns_mu_: this can create a memfd.
    std::expected<InodePtr, fex::Errc>
    new_inode(std::uint16_t mode, std::uint32_t uid, std::uint32_t gid,
              std::uint32_t rdev_major, std::uint32_t rdev_minor, std::string target) {
        int fd = -1;
        if (S_ISREG(mode) && !g_cfg.null_io) {
            fd = ::memfd_create("fex-memfs", MFD_CLOEXEC | MFD_NOEXEC_SEAL);
            if (fd < 0)
                return error(errno == EMFILE || errno == ENFILE ? ENOSPC : errno);
        }
        return std::make_shared<Inode>(next_id_.fetch_add(1, std::memory_order_relaxed),
                                       mode, uid, gid, rdev_major, rdev_minor,
                                       std::move(target), fd);
    }

    // A directory changing parents takes its ".." with it.
    static void move_dir(Inode& child, Inode& from, Inode& to) {
        if (!child.is_dir() || &from == &to)
            return;
        from.nlink.fetch_sub(1, std::memory_order_relaxed);
        to.nlink.fetch_add(1, std::memory_order_relaxed);
        child.parent = to.id;
    }

    // Under ns_mu_, for a name of `child` that was just removed from `dir`.
    void drop_link(Inode& dir, Inode& child) {
        if (child.is_dir()) {
            dir.nlink.fetch_sub(1, std::memory_order_relaxed);
            child.nlink.store(0, std::memory_order_relaxed);
        } else {
            child.nlink.fetch_sub(1, std::memory_order_relaxed);
        }
        if (child.nlink.load(std::memory_order_relaxed) == 0 &&
            child.nlookup.load(std::memory_order_relaxed) == 0)
            inodes_.erase(child.id);
    }

    std::expected<void, fex::Errc>
    remove(fex::NodeId parent, std::string_view name, bool is_rmdir) {
        InodePtr child;
        std::unique_lock lk(ns_mu_);
        const InodePtr dir = find(parent);
        if (!dir)
            return error(ESTALE);
        if (!dir->is_dir())
            return error(ENOTDIR);

        const auto it = dir->children.find(std::string{name});
        if (it == dir->children.end())
            return error(ENOENT);
        child = it->second.inode;
        if (is_rmdir && !child->is_dir())
            return error(ENOTDIR);
        if (!is_rmdir && child->is_dir())
            return error(EISDIR);
        if (is_rmdir && !child->children.empty())
            return error(ENOTEMPTY);

        dir->remove_child(it);
        drop_link(*dir, *child);
        child->touch_changed();
        dir->touch_modified();
        return {};
    }

    static void grow_null_size(Inode& in, std::uint64_t end) {
        std::uint64_t cur = in.null_size.load(std::memory_order_relaxed);
        while (end > cur &&
               !in.null_size.compare_exchange_weak(cur, end, std::memory_order_relaxed))
            ;
    }

    static std::size_t null_read(Inode& in, std::uint64_t off, std::span<std::byte> out) {
        const std::uint64_t size = in.null_size.load(std::memory_order_relaxed);
        if (off >= size)
            return 0;
        const std::size_t len = std::min<std::uint64_t>(out.size(), size - off);
        for (std::size_t pos = 0; pos < len; ) {
            const std::size_t chunk = std::min(len - pos, g_null_buf.size());
            std::memcpy(out.data() + pos, g_null_buf.data(), chunk);
            pos += chunk;
        }
        return len;
    }

    static std::size_t null_write(Inode& in, std::uint64_t off, std::span<const std::byte> data) {
        unsigned char sum = 0;
        for (std::size_t i = 0; i < data.size(); i += 64)
            sum = static_cast<unsigned char>(sum ^ std::to_integer<unsigned char>(data[i]));
        g_null_sink = sum;
        grow_null_size(in, off + data.size());
        return data.size();
    }

    mutable std::shared_mutex ns_mu_;
    std::unordered_map<std::uint64_t, InodePtr> inodes_;
    std::atomic<std::uint64_t> next_id_{fex::to_underlying(fex::NodeId::root) + 1};
};

// Fires storms of invalidations at random files the kernel knows, from a thread
// of its own: a notification can wait for a request served by the workers.
class Invalidator {
public:
    Invalidator(MemFs& fs, fex::Session& session) : fs_(fs), session_(session) {}
    ~Invalidator() { stop(); }

    Invalidator(const Invalidator&)            = delete;
    Invalidator& operator=(const Invalidator&) = delete;

    void start() {
        thread_ = std::thread([this] { run(); });
    }

    void stop() {
        if (!thread_.joinable())
            return;
        {
            std::lock_guard lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }

private:
    void run() {
        std::mt19937 rng(std::random_device{}());
        const unsigned longest = std::max(g_cfg.notify_interval_ms, 1u);
        std::uniform_int_distribution<unsigned> delay(longest / 2 + 1, longest);

        std::unique_lock lk(mu_);
        while (!stop_) {
            // Not on a fixed cadence, and stop() can cut this short.
            if (cv_.wait_for(lk, std::chrono::milliseconds(delay(rng)), [this] { return stop_; }))
                break;
            lk.unlock();
            storm(rng);
            lk.lock();
        }
    }

    bool stopping() {
        std::lock_guard lk(mu_);
        return stop_;
    }

    void storm(std::mt19937& rng) {
        const std::vector<std::uint64_t> files = fs_.known_files();
        if (files.empty())
            return;
        std::uniform_int_distribution<std::size_t> pick(0, files.size() - 1);

        for (unsigned i = 0; i < g_cfg.notify_storm && !stopping(); ++i) {
            const std::uint64_t ino = files[pick(rng)];
            // Just the attributes, or the mapped pages too.
            const std::int64_t off = (rng() & 1) ? -1 : 0;
            const std::error_code ec = session_.notify_inval_inode(to_node(ino), off, 0).get();
            if (!ec) {
                if (g_cfg.debug_io) {
                    const std::chrono::duration<double> t =
                        std::chrono::steady_clock::now() - g_start_time;
                    std::fprintf(stderr, "[%10.3f] memfs NOTIFY ino=%llu scope=%s\n", t.count(),
                                 (unsigned long long)ino, off < 0 ? "attr" : "data+attr");
                }
                continue;
            }
            // Gone from the kernel by now: another one may still be there.
            if (ec.value() == ENOENT)
                continue;
            // No session, or not any more: all the others would fail the same.
            if (ec.value() == ENOTCONN || ec.value() == ECANCELED)
                break;
            std::fprintf(stderr, "memfs: notify_inval_inode(ino=%llu): %s\n",
                         (unsigned long long)ino, ec.message().c_str());
        }
    }

    MemFs&                  fs_;
    fex::Session&           session_;
    std::thread             thread_;
    std::mutex              mu_;
    std::condition_variable cv_;
    bool                    stop_ = false;
};

// What the kernel allows: fuse_init_out.max_pages is a u16.
unsigned max_write_ceiling() {
    unsigned pages = 0;
    if (FILE* f = std::fopen("/proc/sys/fs/fuse/max_pages_limit", "re")) {
        if (std::fscanf(f, "%u", &pages) != 1)
            pages = 0;
        std::fclose(f);
    }
    if (pages == 0)
        pages = 256;
    return std::min(pages, 65535u) * kBlockSize;
}

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s [-f|--foreground] [-o option[,option...]] <mountpoint>\n"
        "\n"
        "Mounts a fusex filesystem at <mountpoint> that keeps everything in\n"
        "memory. Nothing is left when the daemon ends.\n"
        "\n"
        "  -f, --foreground        stay in foreground (do not daemonize)\n"
        "  -h, --help              this help\n"
        "\n"
        "  -o max_write=N          largest request in bytes (default: the ceiling\n"
        "                          from /proc/sys/fs/fuse/max_pages_limit)\n"
        "  -o threads=N            ring worker threads (default: one per CPU, at\n"
        "                          most 32)\n"
        "  -o queue_depth=N        ring entries per queue (default 32)\n"
        "  -o null_io              no data store, to measure the interface: writes\n"
        "                          read the buffer, reads return random data, files\n"
        "                          only remember their size\n"
        "  -o debug_io             log every read and write (offset, size, end) to\n"
        "                          stderr with a timestamp; use with -f\n"
        "  -o notify_inval         run a thread that, at random intervals, fires a\n"
        "                          storm of invalidations at random files the kernel\n"
        "                          knows (peer node simulation)\n"
        "  -o notify_interval_ms=N upper bound on the random delay between storms\n"
        "                          (default 1000)\n"
        "  -o notify_storm=N       invalidations fired back-to-back in each storm\n"
        "                          (default 64)\n",
        argv0);
}

bool parse_options(std::string_view list) {
    while (!list.empty()) {
        const std::size_t comma = list.find(',');
        const std::string_view opt = list.substr(0, comma);
        list = comma == list.npos ? std::string_view{} : list.substr(comma + 1);

        const std::size_t eq = opt.find('=');
        const std::string_view key = opt.substr(0, eq);
        const std::string value{eq == opt.npos ? std::string_view{} : opt.substr(eq + 1)};
        const auto number = [&](unsigned& dst) {
            char* end = nullptr;
            const unsigned long v = std::strtoul(value.c_str(), &end, 0);
            if (value.empty() || *end || v > 0xffffffffUL) {
                std::fprintf(stderr, "bad value in option: %.*s\n", (int)opt.size(), opt.data());
                return false;
            }
            dst = static_cast<unsigned>(v);
            return true;
        };

        bool good;
        if (key == "null_io") {
            g_cfg.null_io = good = true;
        } else if (key == "debug_io") {
            g_cfg.debug_io = good = true;
        } else if (key == "notify_inval") {
            g_cfg.notify_inval = good = true;
        } else if (key == "notify_interval_ms") {
            good = number(g_cfg.notify_interval_ms);
        } else if (key == "notify_storm") {
            good = number(g_cfg.notify_storm);
        } else if (key == "max_write") {
            good = number(g_cfg.max_write);
        } else if (key == "threads") {
            good = number(g_cfg.threads);
        } else if (key == "queue_depth") {
            good = number(g_cfg.queue_depth);
        } else {
            std::fprintf(stderr, "unknown option: %.*s\n", (int)opt.size(), opt.data());
            good = false;
        }
        if (!good)
            return false;
    }
    return true;
}

}  // anonymous

int main(int argc, char** argv)
{
    bool foreground = false;
    int ai = 1;
    for (; ai < argc; ++ai) {
        const std::string_view a = argv[ai];
        if (a == "-f" || a == "--foreground") {
            foreground = true;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else if (a == "-o") {
            if (ai + 1 >= argc) {
                std::fprintf(stderr, "-o requires an argument\n");
                return 2;
            }
            if (!parse_options(argv[++ai]))
                return 2;
        } else if (a.starts_with("-o")) {
            if (!parse_options(a.substr(2)))
                return 2;
        } else if (a.starts_with("-")) {
            std::fprintf(stderr, "unknown option: %s\n", argv[ai]);
            usage(argv[0]);
            return 2;
        } else {
            break;
        }
    }
    if (argc - ai != 1) {
        usage(argv[0]);
        return 2;
    }
    const char* mountpoint = argv[ai];

    if (g_cfg.max_write == 0)
        g_cfg.max_write = max_write_ceiling();
    // Whole pages, at least one: a READLINK needs that much in a ring entry.
    g_cfg.max_write = std::max((g_cfg.max_write + kBlockSize - 1) / kBlockSize, 1u) * kBlockSize;

    if (g_cfg.null_io) {
        g_null_buf.resize(kNullBufSize);
        std::mt19937 rng(0);
        for (auto& byte : g_null_buf)
            byte = static_cast<std::byte>(rng());
    }

    // One memfd per regular file.
    struct rlimit rl;
    if (::getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        (void)::setrlimit(RLIMIT_NOFILE, &rl);
    }

    MemFs fs;

    fex::SessionOptions opts;
    opts.mountpoint          = mountpoint;
    opts.fsname              = "fex-memfs";
    opts.source              = "fex-memfs";
    opts.uring_threads       = g_cfg.threads;
    opts.uring_queue_depth   = std::max(g_cfg.queue_depth, 1u);
    opts.uring_payload_bytes = g_cfg.max_write;

    fex::Session session(std::move(opts));
    fex_example::install_signal_handlers(session);

    // From init(), not from here: the mount may be in a child by then.
    Invalidator invalidator(fs, session);
    if (g_cfg.notify_inval)
        fs.on_init = [&] { invalidator.start(); };

    const int rc = fex_example::run_session(session, fs, mountpoint, foreground, "fex-memfs");
    invalidator.stop();
    return rc;
}
