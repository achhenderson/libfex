// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// notify_test.cpp - end to end test of a fusex mount and the notifications.
//
// Usage (as root, on a kernel with fusex):
//
//     fex-notify-test <empty_dir>
//
// Mounts an in-memory filesystem on <empty_dir>. First the behavior a daemon
// relies on: direct reads and writes, mappings, exec, sync and timestamps.
// Then the notifications: the test changes the server's state directly, checks
// that the kernel doesn't know yet, sends a notification, and checks that the
// kernel now shows the change. Prints "ok" or "FAIL" per check and exits
// non-zero on any FAIL. A check that hangs in the kernel ends the test through
// alarm().

#include <fex/fex.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <linux/falloc.h>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using namespace std::chrono_literals;

namespace {

fex::NodeId to_node(std::uint64_t n) { return static_cast<fex::NodeId>(n); }

const std::size_t kPage = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));

constexpr std::uint64_t kDirFh = 77;

class MemFs final : public fex::Filesystem {
public:
    MemFs() {
        auto& root = nodes_[1];
        root.mode  = S_IFDIR | 0755;
        root.nlink = 2;
        root.nlookup = 1;
        root.atime = root.mtime = root.ctime = stamp();
    }

    // ---- test side: change the server's state, bypassing the kernel ----

    std::uint64_t add_file(const std::string& name, std::string data,
                           std::uint16_t perm = 0644) {
        std::lock_guard lk(mu_);
        const std::uint64_t id = next_id_++;
        auto& n = nodes_[id];
        n.mode  = S_IFREG | perm;
        n.nlink = 1;
        n.data  = std::move(data);
        n.atime = n.mtime = n.ctime = stamp();
        nodes_[1].children[name] = id;
        return id;
    }
    void remove(const std::string& name) {
        std::lock_guard lk(mu_);
        auto& c = nodes_[1].children;
        auto it = c.find(name);
        if (it != c.end()) {
            --nodes_[it->second].nlink;
            c.erase(it);
        }
    }
    void set_data(std::uint64_t id, std::string data) {
        std::lock_guard lk(mu_);
        auto& n = nodes_[id];
        n.data = std::move(data);
        n.mtime = n.ctime = stamp();
    }
    void set_mode(std::uint64_t id, std::uint16_t perm) {
        std::lock_guard lk(mu_);
        auto& n = nodes_[id];
        n.mode = static_cast<std::uint16_t>((n.mode & S_IFMT) | perm);
        n.ctime = stamp();
    }
    std::string data(std::uint64_t id) {
        std::lock_guard lk(mu_);
        return nodes_[id].data;
    }
    std::uint16_t mode(std::uint64_t id) {
        std::lock_guard lk(mu_);
        return nodes_[id].mode;
    }
    std::uint64_t nlookup(std::uint64_t id) {
        std::lock_guard lk(mu_);
        return nodes_[id].nlookup;
    }
    bool has_child(const std::string& name) {
        std::lock_guard lk(mu_);
        return nodes_[1].children.count(name) != 0;
    }
    std::uint64_t child(const std::string& name) {
        std::lock_guard lk(mu_);
        auto& c = nodes_[1].children;
        auto it = c.find(name);
        return it == c.end() ? 0 : it->second;
    }
    std::int64_t atime(std::uint64_t id) {
        std::lock_guard lk(mu_);
        return nodes_[id].atime.sec;
    }
    std::int64_t mtime(std::uint64_t id) {
        std::lock_guard lk(mu_);
        return nodes_[id].mtime.sec;
    }
    std::int64_t ctime(std::uint64_t id) {
        std::lock_guard lk(mu_);
        return nodes_[id].ctime.sec;
    }

    std::atomic<std::uint64_t> reads{0};
    std::atomic<std::uint64_t> writes{0};
    std::atomic<std::uint64_t> largest_read{0};
    std::atomic<std::uint64_t> largest_write{0};
    std::atomic<std::uint64_t> lookups{0};
    std::atomic<std::uint64_t> readdirs{0};
    std::atomic<std::uint64_t> readlinks{0};
    std::atomic<std::uint64_t> fsyncs{0};
    std::atomic<std::uint64_t> fdatasyncs{0};
    std::atomic<std::uint64_t> fsyncdirs{0};
    std::atomic<std::uint64_t> syncfs_calls{0};
    std::atomic<std::uint64_t> last_dir_fh{0};
    // What fsync() answers, 0 for success.
    std::atomic<int> sync_error{0};

    // ---- kernel side ---------------------------------------------------

    std::expected<fex::EntryOut, fex::Errc> lookup_root(const fex::Context&) override {
        fex::EntryOut e;
        e.nodeid = fex::NodeId::root;
        return e;
    }

    std::expected<fex::EntryOut, fex::Errc>
    lookupx(const fex::Context&, fex::NodeId parent, std::string_view name) override {
        ++lookups;
        std::lock_guard lk(mu_);
        auto pit = nodes_.find(fex::to_underlying(parent));
        if (pit == nodes_.end())
            return std::unexpected{static_cast<fex::Errc>(ESTALE)};

        fex::EntryOut e;
        auto it = pit->second.children.find(std::string{name});
        if (it == pit->second.children.end()) {
            e.negative = true;
            return e;
        }
        ++nodes_[it->second].nlookup;
        e.nodeid = to_node(it->second);
        return e;
    }

    void forget(fex::NodeId n, std::uint64_t nlookup) noexcept override {
        std::lock_guard lk(mu_);
        auto it = nodes_.find(fex::to_underlying(n));
        if (it != nodes_.end())
            it->second.nlookup -= std::min(nlookup, it->second.nlookup);
    }

    std::expected<fex::StatxOut, fex::Errc>
    statx(const fex::Context&, fex::NodeId n) override {
        std::lock_guard lk(mu_);
        auto it = nodes_.find(fex::to_underlying(n));
        if (it == nodes_.end())
            return std::unexpected{static_cast<fex::Errc>(ESTALE)};
        return fill(fex::to_underlying(n), it->second);
    }

    std::expected<fex::StatxOut, fex::Errc>
    setstatx(const fex::Context&, fex::NodeId n, fex::FileHandle,
             const fex::SetStatxIn& in) override {
        std::lock_guard lk(mu_);
        auto it = nodes_.find(fex::to_underlying(n));
        if (it == nodes_.end())
            return std::unexpected{static_cast<fex::Errc>(ESTALE)};
        auto& node = it->second;
        namespace m = fex::statx_mask;
        if (in.mask & m::mode)
            node.mode = static_cast<std::uint16_t>((node.mode & S_IFMT) | (in.mode & 07777));
        if (in.mask & m::uid)   node.uid = in.uid;
        if (in.mask & m::gid)   node.gid = in.gid;
        if (in.mask & m::size)  node.data.resize(in.size);
        if (in.mask & m::atime) node.atime = in.atime;
        if (in.mask & m::mtime) node.mtime = in.mtime;
        if (in.mask & m::ctime) node.ctime = in.ctime;
        return fill(fex::to_underlying(n), node);
    }

    std::expected<fex::EntryOut, fex::Errc>
    mkobjx(const fex::Context&, fex::NodeId parent, const fex::MkobjxIn& in) override {
        std::lock_guard lk(mu_);
        const std::uint64_t id = next_id_++;
        auto& n = nodes_[id];
        n.mode    = in.stat.mode;
        n.uid     = in.stat.uid;
        n.gid     = in.stat.gid;
        n.nlink   = S_ISDIR(in.stat.mode) ? 2 : 1;
        n.nlookup = 1;
        n.atime   = n.mtime = n.ctime = stamp();
        // The size of a symlink is the length of its target.
        n.data    = std::string{in.link_target};
        auto& p = nodes_[fex::to_underlying(parent)];
        p.children[std::string{in.name}] = id;
        p.mtime = p.ctime = stamp();
        fex::EntryOut e;
        e.nodeid = to_node(id);
        return e;
    }

    std::expected<void, fex::Errc>
    unlink(const fex::Context&, fex::NodeId parent, std::string_view name) override {
        std::lock_guard lk(mu_);
        auto& p = nodes_[fex::to_underlying(parent)];
        auto it = p.children.find(std::string{name});
        if (it == p.children.end())
            return std::unexpected{fex::Errc::no_such_file_or_directory};
        auto& n = nodes_[it->second];
        if (n.nlink)
            --n.nlink;
        n.ctime = stamp();
        p.children.erase(it);
        p.mtime = p.ctime = stamp();
        return {};
    }

    std::expected<void, fex::Errc>
    link(const fex::Context&, fex::NodeId oldnodeid, fex::NodeId newparent,
         std::string_view newname) override {
        std::lock_guard lk(mu_);
        auto& n = nodes_[fex::to_underlying(oldnodeid)];
        ++n.nlink;
        n.ctime = stamp();
        auto& p = nodes_[fex::to_underlying(newparent)];
        p.children[std::string{newname}] = fex::to_underlying(oldnodeid);
        p.mtime = p.ctime = stamp();
        return {};
    }

    std::expected<std::string, fex::Errc>
    readlink(const fex::Context&, fex::NodeId n) override {
        ++readlinks;
        std::lock_guard lk(mu_);
        return nodes_[fex::to_underlying(n)].data;
    }

    std::expected<std::size_t, fex::Errc>
    read(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
         std::span<std::byte> out) override {
        ++reads;
        std::lock_guard lk(mu_);
        largest_read = std::max<std::uint64_t>(largest_read, out.size());
        auto& node = nodes_[fex::to_underlying(n)];
        node.atime = stamp();
        const auto& d = node.data;
        if (off >= d.size())
            return std::size_t{0};
        const std::size_t len = std::min<std::size_t>(out.size(), d.size() - off);
        std::memcpy(out.data(), d.data() + off, len);
        return len;
    }

    std::expected<std::size_t, fex::Errc>
    write(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
          std::span<const std::byte> in) override {
        ++writes;
        std::lock_guard lk(mu_);
        largest_write = std::max<std::uint64_t>(largest_write, in.size());
        auto& node = nodes_[fex::to_underlying(n)];
        auto& d = node.data;
        if (d.size() < off + in.size())
            d.resize(off + in.size());
        std::memcpy(d.data() + off, in.data(), in.size());
        node.mtime = node.ctime = stamp();
        return in.size();
    }

    std::expected<void, fex::Errc>
    fallocate(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint32_t mode,
              std::uint64_t off, std::uint64_t len) override {
        std::lock_guard lk(mu_);
        auto& node = nodes_[fex::to_underlying(n)];
        auto& d = node.data;
        if (!(mode & FALLOC_FL_KEEP_SIZE) && d.size() < off + len)
            d.resize(off + len);
        if ((mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)) && off < d.size())
            std::memset(d.data() + off, 0, std::min<std::uint64_t>(len, d.size() - off));
        node.mtime = node.ctime = stamp();
        return {};
    }

    std::expected<void, fex::Errc>
    fsync(const fex::Context&, fex::NodeId, fex::FileHandle, bool datasync) override {
        ++(datasync ? fdatasyncs : fsyncs);
        if (const int e = sync_error.load())
            return std::unexpected{static_cast<fex::Errc>(e)};
        return {};
    }

    std::expected<void, fex::Errc>
    fsyncdir(const fex::Context&, fex::NodeId, fex::FileHandle fh, bool) override {
        ++fsyncdirs;
        last_dir_fh = fex::to_underlying(fh);
        return {};
    }

    std::expected<void, fex::Errc> syncfs(const fex::Context&) override {
        ++syncfs_calls;
        return {};
    }

    std::expected<fex::OpenOut, fex::Errc>
    opendir(const fex::Context&, fex::NodeId) override {
        return fex::OpenOut{.fh = static_cast<fex::FileHandle>(kDirFh)};
    }

    std::expected<void, fex::Errc>
    readdir(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
            fex::DirentWriter& out) override {
        ++readdirs;
        std::lock_guard lk(mu_);
        std::uint64_t i = 0;
        for (const auto& [name, id] : nodes_[fex::to_underlying(n)].children) {
            ++i;
            if (i <= off)
                continue;
            if (!out.add(name, id, i, DT_UNKNOWN))
                break;
        }
        return {};
    }

    // No xattrs: this also answers the ACL lookups the kernel makes.
    std::expected<std::size_t, fex::Errc>
    getxattr(const fex::Context&, fex::NodeId, std::string_view, std::span<std::byte>) override {
        return std::unexpected{static_cast<fex::Errc>(ENODATA)};
    }
    std::expected<std::size_t, fex::Errc>
    listxattr(const fex::Context&, fex::NodeId, std::span<std::byte>) override {
        return std::size_t{0};
    }

private:
    struct Node {
        std::uint16_t mode = 0;
        std::uint32_t uid = 0, gid = 0, nlink = 0;
        std::string   data;
        std::map<std::string, std::uint64_t> children;
        fex::Timespec atime, mtime, ctime;
        std::uint64_t nlookup = 0;
    };

    // Every change gets a time of its own, whatever the clock's resolution.
    fex::Timespec stamp() { return fex::Timespec{++clock_, 0}; }

    static fex::StatxOut fill(std::uint64_t id, const Node& n) {
        fex::StatxOut out;
        out.mask    = fex::statx_mask::basic;
        out.blksize = 4096;
        out.nlink   = n.nlink;
        out.uid     = n.uid;
        out.gid     = n.gid;
        out.mode    = n.mode;
        out.ino     = id;
        out.size    = n.data.size();
        out.blocks  = (n.data.size() + 511) / 512;
        out.atime   = n.atime;
        out.mtime   = n.mtime;
        out.ctime   = n.ctime;
        return out;
    }

    std::mutex mu_;
    std::unordered_map<std::uint64_t, Node> nodes_;
    std::uint64_t next_id_ = 2;
    std::int64_t clock_ = 1000000;
};

// A mapping of a file for the length of a scope.
class Mapping {
public:
    Mapping(int fd, std::size_t len, int prot, int flags = MAP_SHARED)
        : len_(len), addr_(::mmap(nullptr, len, prot, flags, fd, 0)) {}
    ~Mapping() {
        if (ok())
            ::munmap(addr_, len_);
    }
    Mapping(const Mapping&)            = delete;
    Mapping& operator=(const Mapping&) = delete;

    bool  ok() const { return addr_ != MAP_FAILED; }
    void* addr() const { return addr_; }
    volatile char& operator[](std::size_t i) { return static_cast<volatile char*>(addr_)[i]; }
    // Fault the page in.
    void touch(std::size_t i) {
        const char c = (*this)[i];
        (void)c;
    }

private:
    std::size_t len_;
    void*       addr_;
};

int g_failures = 0;

void check(bool good, const std::string& what) {
    std::printf("%s - %s\n", good ? "ok  " : "FAIL", what.c_str());
    std::fflush(stdout);
    if (!good)
        ++g_failures;
}

// A notification that doesn't complete is a failed check, not a hang here.
void check_notify(std::future<std::error_code> fut, const std::string& what) {
    if (fut.wait_for(30s) != std::future_status::ready) {
        check(false, what + ": no completion");
        return;
    }
    const auto ec = fut.get();
    check(!ec, what + (ec ? ": " + ec.message() : std::string{}));
}

std::string read_all(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return "<open: " + std::string{::strerror(errno)} + ">";
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0)
        out.append(buf, static_cast<std::size_t>(n));
    if (n < 0)
        out = "<read: " + std::string{::strerror(errno)} + ">";
    ::close(fd);
    return out;
}

struct ::stat stat_of(const std::string& path) {
    struct ::stat st{};
    (void)::stat(path.c_str(), &st);
    return st;
}

off_t size_of(const std::string& path) {
    struct ::stat st;
    return ::stat(path.c_str(), &st) == 0 ? st.st_size : -1;
}

unsigned perm_of(const std::string& path) {
    struct ::stat st;
    return ::stat(path.c_str(), &st) == 0 ? (st.st_mode & 07777u) : 0u;
}

bool exists(const std::string& path) {
    struct ::stat st;
    return ::stat(path.c_str(), &st) == 0;
}

std::vector<std::string> list_dir(const std::string& path) {
    std::vector<std::string> names;
    if (DIR* d = ::opendir(path.c_str())) {
        while (struct dirent* de = ::readdir(d))
            names.emplace_back(de->d_name);
        ::closedir(d);
    }
    return names;
}

template <typename Pred>
bool eventually(Pred pred) {
    for (int i = 0; i < 100; ++i) {
        if (pred())
            return true;
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

char read_byte(int fd, off_t off) {
    char c = '?';
    return ::pread(fd, &c, 1, off) == 1 ? c : '?';
}

bool write_byte(int fd, char c, off_t off) {
    return ::pwrite(fd, &c, 1, off) == 1;
}

// Keep the attributes invalid while the file grows: fetching them must not lose
// an append.
void test_append_under_invalidation(MemFs& fs, fex::Session& session, const std::string& mnt) {
    const std::string path = mnt + "/append";
    const std::uint64_t id = fs.add_file("append", "");
    const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND);
    check(fd >= 0, "open for append");
    if (fd < 0)
        return;

    std::atomic<bool> done{false};
    std::thread inval([&] {
        while (!done.load()) {
            session.notify_inval_inode(to_node(id), -1, 0).wait();
            (void)size_of(path);
        }
    });

    constexpr std::size_t kBlock = 4096;
    constexpr std::size_t kBlocks = 2000;
    char block[kBlock];
    bool written = true;
    for (std::size_t i = 0; i < kBlocks && written; ++i) {
        std::memset(block, 'a' + static_cast<int>(i % 26), sizeof(block));
        written = ::write(fd, block, sizeof(block)) == static_cast<ssize_t>(sizeof(block));
    }
    done.store(true);
    inval.join();
    check(written, "append while the attributes keep being invalidated");
    check(::fsync(fd) == 0, "fsync");
    ::close(fd);

    check(size_of(path) == static_cast<off_t>(kBlock * kBlocks), "no append lost in the size");
    const std::string data = fs.data(id);
    bool same = data.size() == kBlock * kBlocks;
    for (std::size_t i = 0; i < kBlocks && same; ++i) {
        const char want = static_cast<char>('a' + static_cast<int>(i % 26));
        same = data[i * kBlock] == want && data[i * kBlock + kBlock - 1] == want;
    }
    check(same, "no append lost in the data");
}

// The object has another name left: only the count of names goes down.
void test_delete_hard_link(MemFs& fs, fex::Session& session, const std::string& mnt) {
    const std::string a = mnt + "/link-a", b = mnt + "/link-b";
    const std::uint64_t id = fs.add_file("link-a", "L");
    check(::link(a.c_str(), b.c_str()) == 0, "hard link");
    struct ::stat st;
    check(::stat(b.c_str(), &st) == 0 && st.st_nlink == 2, "two names");

    fs.remove("link-a");
    check_notify(session.notify_delete(fex::NodeId::root, to_node(id), "link-a"),
                 "DELETE of a hard link");
    check(!exists(a), "that name is gone");
    check(::stat(b.c_str(), &st) == 0 && st.st_nlink == 1, "the other name counts one link");
    check(read_all(b) == "L", "the data is still there");
    check(::unlink(b.c_str()) == 0, "unlink the other name");
    check(eventually([&] { return fs.nlookup(id) == 0; }), "FORGET after the last name");
}

bool wait_mounted(const std::string& mnt, dev_t before,
                  std::future<std::error_code>& run_result) {
    return eventually([&] {
        struct ::stat st;
        return run_result.wait_for(0s) == std::future_status::ready ||
               (::stat(mnt.c_str(), &st) == 0 && st.st_dev != before);
    }) && run_result.wait_for(0s) != std::future_status::ready;
}

// Nothing writes back on close: stop() has to, before it unmounts.
void test_stop_writes_back(const std::string& mnt, dev_t before) {
    MemFs fs;
    fex::SessionOptions opts;
    opts.mountpoint = mnt;
    opts.source     = "fex-notify-test";
    fex::Session session(std::move(opts));

    std::promise<std::error_code> run_done;
    auto run_result = run_done.get_future();
    std::thread runner([&] { run_done.set_value(session.run(fs)); });

    const bool mounted = wait_mounted(mnt, before, run_result);
    check(mounted, "second mount");
    bool stored = false;
    if (mounted) {
        const std::string path = mnt + "/dirty";
        const int fd = ::open(path.c_str(), O_CREAT | O_RDWR, 0644);
        if (fd >= 0 && ::ftruncate(fd, 5) == 0) {
            Mapping m(fd, 5, PROT_READ | PROT_WRITE);
            if (m.ok()) {
                std::memcpy(m.addr(), "dirty", 5);
                stored = true;
            }
        }
        if (fd >= 0)
            ::close(fd);
        check(stored, "a store through a mapping, without msync");
    }

    session.stop();
    const bool stopped = run_result.wait_for(60s) == std::future_status::ready;
    check(stopped, "stop() ends the session");
    if (stopped) {
        runner.join();
        const auto ec = run_result.get();
        check(!ec, "clean end after stop()" + (ec ? ": " + ec.message() : std::string{}));
        if (stored)
            check(fs.data(fs.child("dirty")) == "dirty", "stop() wrote back the dirty page");
        check(fs.syncfs_calls.load() > 0, "stop() synced the server");
        struct ::stat st;
        check(::stat(mnt.c_str(), &st) == 0 && st.st_dev == before, "stop() unmounted");
    } else {
        ::umount2(mnt.c_str(), MNT_FORCE | MNT_DETACH);
        runner.join();
    }
}

void test_kernel_ops(MemFs& fs, const std::string& mnt) {
    const std::string path = mnt + "/created";
    int fd = ::open(path.c_str(), O_CREAT | O_WRONLY, 0640);
    check(fd >= 0, "create through the kernel (MKOBJX)");
    if (fd < 0)
        return;
    check(::write(fd, "abc", 3) == 3, "write");
    const std::uint64_t id = fs.child("created");
    check(id != 0 && fs.data(id) == "abc", "the write reached the server");
    check(::fsync(fd) == 0, "fsync");
    ::close(fd);
    check(read_all(path) == "abc", "read back");
    check(::chmod(path.c_str(), 0600) == 0 && (fs.mode(id) & 07777) == 0600,
          "chmod reached the server (SETSTATX)");
    check(::unlink(path.c_str()) == 0 && !fs.has_child("created"), "unlink");
    check(!exists(path), "gone after unlink");
    check(eventually([&] { return fs.nlookup(id) == 0; }), "FORGET after unlink");
}

// read(2) and write(2) don't use the page cache.
void test_direct_io(MemFs& fs, fex::Session& session, const std::string& mnt) {
    const std::string path = mnt + "/direct";
    const std::uint64_t id = fs.add_file("direct", "0123456789");

    std::uint64_t reads = fs.reads.load();
    check(read_all(path) == "0123456789" && fs.reads.load() > reads, "a read reaches the server");
    reads = fs.reads.load();
    check(read_all(path) == "0123456789" && fs.reads.load() > reads,
          "and so does the next one, nothing is cached");

    const int fd = ::open(path.c_str(), O_RDWR);
    check(fd >= 0, "open for direct I/O");
    if (fd < 0)
        return;

    check(::pwrite(fd, "abc", 3, 0) == 3 && fs.data(id) == "abc3456789",
          "a write is at the server when it returns");
    check(read_all(path) == "abc3456789", "read that back");

    // All the segments fit one request.
    char a[] = "A", b[] = "B", c[] = "C";
    struct iovec iov[3] = {{a, 1}, {b, 1}, {c, 1}};
    const std::uint64_t writes = fs.writes.load();
    check(::pwritev(fd, iov, 3, 0) == 3 && fs.writes.load() == writes + 1 &&
          fs.data(id).substr(0, 3) == "ABC", "the segments of a writev go in one request");

    std::string big(3u << 20, '\0');
    for (std::size_t i = 0; i < big.size(); ++i)
        big[i] = static_cast<char>('a' + (i / 4099) % 26);
    const auto big_len = static_cast<ssize_t>(big.size());
    check(::pwrite(fd, big.data(), big.size(), 0) == big_len && fs.data(id) == big,
          "a large write");
    check(fs.largest_write.load() > kPage && fs.largest_write.load() <= 1u << 20,
          "goes in requests larger than a page and up to max_write");
    std::string back(big.size(), '\0');
    check(::pread(fd, back.data(), back.size(), 0) == big_len && back == big, "a large read");
    check(fs.largest_read.load() > kPage, "goes in requests larger than a page");

    const int dfd = ::open(path.c_str(), O_RDONLY | O_DIRECT);
    check(dfd >= 0, "open with O_DIRECT");
    if (dfd >= 0) {
        check(read_byte(dfd, 1) == big[1], "O_DIRECT doesn't need alignment");
        ::close(dfd);
    }

    // The kernel still has the large size, the server decides.
    fs.set_data(id, "short");
    check(read_all(path) == "short", "a short read from the server ends the read, no zeros");
    check_notify(session.notify_inval_inode(to_node(id), -1, 0), "INVAL_INODE for the new size");
    check(size_of(path) == 5, "the new size");

    // Through the splice paths of both files.
    const std::string copy = mnt + "/direct-copy";
    const int ofd = ::open(copy.c_str(), O_CREAT | O_WRONLY, 0644);
    check(ofd >= 0, "create a copy");
    if (ofd >= 0) {
        off64_t in_off = 0, out_off = 0;
        check(::copy_file_range(fd, &in_off, ofd, &out_off, 5, 0) == 5 &&
              fs.data(fs.child("direct-copy")) == "short", "copy_file_range");
        ::close(ofd);
    }
    ::close(fd);
}

// The target isn't in the page cache either.
void test_symlink(MemFs& fs, const std::string& mnt) {
    const std::string link = mnt + "/sl";
    fs.add_file("sl-target", "through");
    check(::symlink("sl-target", link.c_str()) == 0, "symlink (MKOBJX)");

    struct ::stat st;
    check(::lstat(link.c_str(), &st) == 0 && S_ISLNK(st.st_mode) && st.st_size == 9, "lstat");
    char buf[64];
    check(::readlink(link.c_str(), buf, sizeof(buf)) == 9 &&
          std::string_view(buf, 9) == "sl-target", "readlink");
    const std::uint64_t readlinks = fs.readlinks.load();
    check(::readlink(link.c_str(), buf, sizeof(buf)) == 9 && fs.readlinks.load() > readlinks,
          "the next readlink reaches the server too");
    check(read_all(link) == "through", "follow it");
}

// Durability is the server's, these have to reach it.
void test_sync(MemFs& fs, const std::string& mnt) {
    const std::string path = mnt + "/synced";
    fs.add_file("synced", "s");

    int fd = ::open(path.c_str(), O_WRONLY);
    check(fd >= 0, "open for sync");
    if (fd < 0)
        return;
    std::uint64_t n = fs.fsyncs.load();
    check(::fsync(fd) == 0 && fs.fsyncs.load() == n + 1, "fsync reaches the server");
    n = fs.fdatasyncs.load();
    check(::fdatasync(fd) == 0 && fs.fdatasyncs.load() == n + 1, "fdatasync reaches the server");

    fs.sync_error = EIO;
    errno = 0;
    check(::fsync(fd) == -1 && errno == EIO, "fsync gets the server's error");
    fs.sync_error = ENOSYS;
    check(::fsync(fd) == 0, "fsync succeeds without an implementation");
    fs.sync_error = 0;
    ::close(fd);

    fd = ::open(path.c_str(), O_WRONLY | O_SYNC);
    n = fs.fsyncs.load();
    check(fd >= 0 && write_byte(fd, 's', 0) && fs.fsyncs.load() == n + 1,
          "an O_SYNC write ends in an fsync");
    if (fd >= 0)
        ::close(fd);

    fd = ::open(path.c_str(), O_WRONLY | O_DSYNC);
    n = fs.fdatasyncs.load();
    check(fd >= 0 && write_byte(fd, 's', 0) && fs.fdatasyncs.load() == n + 1,
          "an O_DSYNC write ends in an fdatasync");
    if (fd >= 0)
        ::close(fd);

    const int dfd = ::open(mnt.c_str(), O_RDONLY | O_DIRECTORY);
    check(dfd >= 0, "open a directory for sync");
    if (dfd < 0)
        return;
    n = fs.fsyncdirs.load();
    check(::fsync(dfd) == 0 && fs.fsyncdirs.load() == n + 1 && fs.last_dir_fh.load() == kDirFh,
          "fsync of a directory is FSYNCDIR with its handle");
    n = fs.syncfs_calls.load();
    check(::syncfs(dfd) == 0 && fs.syncfs_calls.load() > n, "syncfs reaches the server");
    ::close(dfd);
}

// Mappings are the only users of the page cache, and read(2) and write(2) have
// to stay coherent with them.
void test_mmap(MemFs& fs, fex::Session& session, const std::string& mnt) {
    const std::string path = mnt + "/mapped";
    const std::uint64_t id = fs.add_file("mapped", std::string(2 * kPage, 'a'));
    const fex::NodeId node = to_node(id);
    const int fd = ::open(path.c_str(), O_RDWR);
    check(fd >= 0, "open for mapping");
    if (fd < 0)
        return;
    {
        Mapping m(fd, 2 * kPage, PROT_READ | PROT_WRITE);
        check(m.ok(), "mmap, shared and writable");
        if (!m.ok()) {
            ::close(fd);
            return;
        }

        // ---- the page cache --------------------------------------------
        check(m[0] == 'a', "a fault reads the data");
        std::uint64_t reads = fs.reads.load();
        check(m[1] == 'a' && fs.reads.load() == reads, "the page stays cached");
        check(read_byte(fd, 0) == 'a' && fs.reads.load() > reads, "read(2) still asks the server");

        // ---- notifications ---------------------------------------------
        fs.set_data(id, std::string(2 * kPage, 'b'));
        check_notify(session.notify_inval_inode(node, -1, 0), "INVAL_INODE, attributes only");
        check(m[0] == 'a', "keeps the mapped page");
        check_notify(session.notify_inval_inode(node), "INVAL_INODE, data");
        check(m[0] == 'b', "drops the mapped page");

        // ---- stores and read(2) ----------------------------------------
        (void)size_of(path);
        m[0] = 'D';
        check(fs.data(id)[0] == 'b', "a store stays in the page");
        check(read_byte(fd, 0) == 'D' && fs.data(id)[0] == 'D',
              "read(2) writes the dirty page back first");

        // ---- write(2) and the mapping ----------------------------------
        check(write_byte(fd, 'W', 0) && m[0] == 'W', "a mapping sees write(2)");
        m[1] = 'S';
        check(write_byte(fd, 'T', 2), "write(2) next to a store in the same page");
        std::string d = fs.data(id);
        check(d[0] == 'W' && d[1] == 'S' && d[2] == 'T', "keeps the store at the server");
        check(m[0] == 'W' && m[1] == 'S' && m[2] == 'T', "and in the mapping");

        // ---- a dirty page isn't lost -----------------------------------
        m[3] = 'L';
        check_notify(session.notify_inval_inode(node), "INVAL_INODE on a dirty page");
        check(fs.data(id)[3] == 'L', "writes it back");
        check(m[3] == 'L', "and the mapping reads it again");

        // ---- durability ------------------------------------------------
        m[4] = 'M';
        std::uint64_t n = fs.fdatasyncs.load();
        check(::msync(m.addr(), kPage, MS_SYNC) == 0 && fs.data(id)[4] == 'M' &&
              fs.fdatasyncs.load() == n + 1, "msync writes back and syncs the server");
        m[5] = 'F';
        n = fs.fsyncs.load();
        check(::fsync(fd) == 0 && fs.data(id)[5] == 'F' && fs.fsyncs.load() == n + 1,
              "fsync writes back and syncs the server");

        // ---- truncate --------------------------------------------------
        const off_t tail = static_cast<off_t>(kPage + 100);
        m[kPage + 100] = 'Z';
        check(::ftruncate(fd, tail) == 0 && fs.data(id).size() == kPage + 100, "truncate");
        check(m[kPage + 100] == 0, "the mapped page is zero past the new EOF");

        // Past EOF in the last page: mappable, but not part of the file.
        m[kPage + 200] = 'X';
        check(::ftruncate(fd, static_cast<off_t>(2 * kPage)) == 0, "grow it");
        check(m[kPage + 200] == 0 && read_byte(fd, static_cast<off_t>(kPage + 200)) == 0 &&
              fs.data(id)[kPage + 200] == 0, "a store past the old EOF is gone");

        check(::ftruncate(fd, tail) == 0, "truncate again");
        m.touch(kPage);
        check(write_byte(fd, 'G', tail) && m[kPage + 100] == 'G',
              "write(2) at EOF shows in the last page");
        m[kPage + 300] = 'Y';
        check(write_byte(fd, 'E', static_cast<off_t>(3 * kPage)) &&
              fs.data(id).size() == 3 * kPage + 1, "write(2) far past EOF");
        check(m[kPage + 300] == 0 && read_byte(fd, static_cast<off_t>(kPage + 300)) == 0,
              "a store past the old EOF is gone here too");

        // ---- fallocate -------------------------------------------------
        m[1] = 'P';
        check(::fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
                          static_cast<off_t>(kPage)) == 0, "punch a hole");
        check(m[1] == 0 && fs.data(id)[1] == 0, "the mapping and the server have the hole");
        check(::fallocate(fd, 0, 0, static_cast<off_t>(4 * kPage)) == 0 &&
              size_of(path) == static_cast<off_t>(4 * kPage), "fallocate grows the file");
    }
    {
        check(write_byte(fd, 'R', 10), "write(2) for a private mapping");
        Mapping p(fd, kPage, PROT_READ | PROT_WRITE, MAP_PRIVATE);
        check(p.ok(), "mmap, private");
        if (p.ok()) {
            check(p[10] == 'R', "reads the file");
            p[10] = 'P';
            check(p[10] == 'P' && read_byte(fd, 10) == 'R' && fs.data(id)[10] == 'R',
                  "a private store stays private");
        }
    }
    check(::fsync(fd) == 0, "fsync before unlink");
    ::close(fd);
    check(::unlink(path.c_str()) == 0, "unlink the mapped file");
    check(eventually([&] { return fs.nlookup(id) == 0; }), "FORGET after the last mapping");
}

// The server owns the times: what it has is what stat shows.
void test_times(MemFs& fs, const std::string& mnt) {
    const std::string path = mnt + "/timed", other = mnt + "/timed-other";
    const std::uint64_t id = fs.add_file("timed", "x");
    const auto shown = [&] {
        const auto st = stat_of(path);
        return st.st_mtim.tv_sec == fs.mtime(id) && st.st_ctim.tv_sec == fs.ctime(id) &&
               st.st_atim.tv_sec == fs.atime(id);
    };
    const auto root_shown = [&] {
        const auto st = stat_of(mnt);
        return st.st_mtim.tv_sec == fs.mtime(1) && st.st_ctim.tv_sec == fs.ctime(1);
    };
    check(shown(), "stat shows the server's times");

    const int fd = ::open(path.c_str(), O_RDWR);
    check(fd >= 0, "open for times");
    if (fd < 0)
        return;

    std::int64_t t = fs.mtime(id);
    const std::string block(8192, 'w');
    check(::pwrite(fd, block.data(), block.size(), 0) == 8192 && fs.mtime(id) != t,
          "the server stamps a write");
    check(shown(), "stat shows that");
    const auto st = stat_of(path);
    check(st.st_size == 8192 && st.st_blocks == 16, "and the size and blocks");

    t = fs.atime(id);
    check(read_all(path) == block && fs.atime(id) != t, "the server stamps a read");
    check(shown(), "stat shows that");
    {
        Mapping m(fd, 8192, PROT_READ | PROT_WRITE);
        check(m.ok(), "mmap for times");
        if (m.ok()) {
            m.touch(0);
            t = fs.mtime(id);
            m[0] = 'q';
            check(fs.mtime(id) == t, "a store isn't at the server yet");
            check(shown() && fs.mtime(id) != t && fs.data(id)[0] == 'q',
                  "stat writes it back and shows the server's stamp");
            t = fs.mtime(id);
            m[1] = 'r';
            check(shown() && fs.mtime(id) != t && fs.data(id)[1] == 'r',
                  "and again for the next store");
        }
    }
    ::close(fd);

    t = fs.mtime(1);
    const int cfd = ::open(other.c_str(), O_CREAT | O_WRONLY, 0644);
    check(cfd >= 0 && fs.mtime(1) != t, "the server stamps the directory on a create");
    if (cfd >= 0)
        ::close(cfd);
    check(root_shown(), "stat of the directory shows that");
    t = fs.mtime(1);
    check(::unlink(other.c_str()) == 0 && fs.mtime(1) != t,
          "the server stamps the directory on an unlink");
    check(root_shown(), "stat of the directory shows that");

    t = fs.ctime(id);
    check(::link(path.c_str(), other.c_str()) == 0 && fs.ctime(id) != t,
          "the server stamps the object on a link");
    check(shown(), "stat shows that");
    t = fs.ctime(id);
    check(::unlink(other.c_str()) == 0 && fs.ctime(id) != t,
          "the server stamps the object on an unlink");
    check(shown(), "stat shows that");

    const struct timespec ts[2] = {{1000, 0}, {2000, 0}};
    check(::utimensat(AT_FDCWD, path.c_str(), ts, 0) == 0 && fs.atime(id) == 1000 &&
          fs.mtime(id) == 2000, "utimensat reaches the server");
    const auto after = stat_of(path);
    check(after.st_atim.tv_sec == 1000 && after.st_mtim.tv_sec == 2000, "stat shows that");
}

// Reads the program through read(2), maps it through the page cache.
void test_exec(MemFs& fs, const std::string& mnt) {
    std::string prog;
    for (const char* real : {"/bin/true", "/usr/bin/true"}) {
        if (::access(real, X_OK) == 0) {
            prog = read_all(real);
            break;
        }
    }
    if (prog.empty()) {
        std::printf("skip - exec: no true(1) to copy\n");
        return;
    }
    const std::string path = mnt + "/true";
    fs.add_file("true", std::move(prog), 0755);

    const pid_t pid = ::fork();
    if (pid == 0) {
        ::execl(path.c_str(), path.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int status = 0;
    check(pid > 0 && ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0, "exec a program from the mount");
}

}  // anonymous

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <empty_dir>\n", argv[0]);
        return 2;
    }
    const std::string mnt = argv[1];
    ::alarm(300);

    struct ::stat before;
    if (::stat(mnt.c_str(), &before) < 0) {
        std::perror("stat mountpoint");
        return 2;
    }

    MemFs fs;
    fex::SessionOptions opts;
    opts.mountpoint = mnt;
    opts.source     = "fex-notify-test";
    fex::Session session(std::move(opts));

    std::promise<std::error_code> run_done;
    auto run_result = run_done.get_future();
    std::thread runner([&] { run_done.set_value(session.run(fs)); });

    const bool mounted = wait_mounted(mnt, before.st_dev, run_result);
    check(mounted, "mount over io-uring (INIT, LOOKUP_ROOT, STATX)");
    if (!mounted) {
        session.stop();
        runner.join();
        if (run_result.valid())
            std::fprintf(stderr, "session: %s\n", run_result.get().message().c_str());
        return 1;
    }

    test_kernel_ops(fs, mnt);
    test_direct_io(fs, session, mnt);
    test_symlink(fs, mnt);
    test_sync(fs, mnt);
    test_mmap(fs, session, mnt);
    test_times(fs, mnt);
    test_exec(fs, mnt);
    test_append_under_invalidation(fs, session, mnt);
    test_delete_hard_link(fs, session, mnt);

    // ---- INVAL_INODE: attributes and data ------------------------------
    const std::string f = mnt + "/f";
    const std::uint64_t fid = fs.add_file("f", "hello");
    const fex::NodeId fnode = to_node(fid);
    check(read_all(f) == "hello", "read a file the server added");

    // A read makes the atime stale, and fetching that shows everything: this
    // stat is what lets the next one show the old state.
    (void)size_of(f);
    fs.set_data(fid, "hello world");
    check(size_of(f) == 5, "server change not visible before the notification");
    check_notify(session.notify_inval_inode(fnode), "INVAL_INODE");
    check(size_of(f) == 11, "new size after INVAL_INODE");
    check(read_all(f) == "hello world", "new data after INVAL_INODE");

    // ---- INVAL_INODE: attributes only ----------------------------------
    (void)perm_of(f);
    fs.set_mode(fid, 0600);
    check(perm_of(f) == 0644, "mode change not visible before the notification");
    check_notify(session.notify_inval_inode(fnode, -1, 0), "INVAL_INODE, attributes only");
    check(perm_of(f) == 0600, "new mode after INVAL_INODE");

    // ---- INVAL_INODE: shrink -------------------------------------------
    fs.set_data(fid, "hi");
    check_notify(session.notify_inval_inode(fnode), "INVAL_INODE after a shrink");
    check(size_of(f) == 2 && read_all(f) == "hi", "new size and data after a shrink");

    fs.set_data(fid, "hello world");
    check_notify(session.notify_inval_inode(fnode), "INVAL_INODE after a grow");
    check(read_all(f) == "hello world", "new data after a grow");

    // ---- INVAL_ENTRY: a cached negative entry --------------------------
    const std::string g = mnt + "/g";
    check(!exists(g), "lookup of a missing name");
    std::uint64_t lookups = fs.lookups.load();
    check(!exists(g) && fs.lookups.load() == lookups, "negative entry is cached");
    const std::uint64_t gid = fs.add_file("g", "G");
    check(!exists(g), "new name not visible before the notification");
    check_notify(session.notify_inval_entry(fex::NodeId::root, "g"), "INVAL_ENTRY");
    check(exists(g) && read_all(g) == "G", "new name visible after INVAL_ENTRY");

    // ---- DELETE --------------------------------------------------------
    fs.remove("g");
    check(exists(g), "removal not visible before the notification");
    check_notify(session.notify_delete(fex::NodeId::root, to_node(gid), "g"), "DELETE");
    check(!exists(g), "name gone after DELETE");
    check(eventually([&] { return fs.nlookup(gid) == 0; }), "FORGET after DELETE");

    // ---- readdir has no cache ------------------------------------------
    const auto has = [&](const std::string& name) {
        const auto names = list_dir(mnt);
        return std::find(names.begin(), names.end(), name) != names.end();
    };
    check(has("f"), "readdir");
    const std::uint64_t readdirs = fs.readdirs.load();
    fs.add_file("h", "H");
    check(has("h") && fs.readdirs.load() > readdirs,
          "readdir shows a new name without a notification");

    // ---- every lookup is counted, FORGET gives all of them back --------
    const std::uint64_t counted = fs.nlookup(fid);
    int fd = ::open(f.c_str(), O_RDONLY);
    check(fd >= 0, "keep the file open");
    check_notify(session.notify_inval_entry(fex::NodeId::root, "f"), "INVAL_ENTRY, name in use");
    check(exists(f) && fs.nlookup(fid) == counted + 1, "the name is looked up again");
    if (fd >= 0)
        ::close(fd);
    {
        const int dfd = ::open(mnt.c_str(), O_RDONLY | O_DIRECTORY);
        check(dfd >= 0 && ::syncfs(dfd) == 0, "syncfs");
        if (dfd >= 0)
            ::close(dfd);
    }

    // ---- PRUNE ---------------------------------------------------------
    const fex::NodeId prune[] = {fnode};
    check_notify(session.notify_prune(prune), "PRUNE");
    check(eventually([&] { return fs.nlookup(fid) == 0; }),
          "FORGET gives back every lookup after PRUNE");

    // ---- unmount -------------------------------------------------------
    // A dirty mapped page goes out with it, and the server gets to sync.
    const std::string last = mnt + "/last";
    const std::uint64_t lastid = fs.add_file("last", std::string(16, '-'));
    fd = ::open(last.c_str(), O_RDWR);
    check(fd >= 0, "open for the last store");
    if (fd >= 0) {
        {
            Mapping m(fd, 16, PROT_READ | PROT_WRITE);
            check(m.ok(), "map for the last store");
            if (m.ok())
                m[0] = 'u';
        }
        ::close(fd);
    }
    const std::uint64_t syncs = fs.syncfs_calls.load();

    check(::umount2(mnt.c_str(), 0) == 0, "umount");
    const bool stopped = run_result.wait_for(30s) == std::future_status::ready;
    check(stopped, "the session ends with the unmount");
    if (!stopped) {
        session.stop();
        ::umount2(mnt.c_str(), MNT_FORCE | MNT_DETACH);
    }
    runner.join();
    if (stopped) {
        const auto ec = run_result.get();
        check(!ec, "clean session end" + (ec ? ": " + ec.message() : std::string{}));
        check(fs.data(lastid)[0] == 'u', "umount wrote back the dirty page");
        check(fs.syncfs_calls.load() > syncs, "umount synced the server");
    }

    test_stop_writes_back(mnt, before.st_dev);

    std::printf("%s\n", g_failures ? "FAILED" : "PASSED");
    return g_failures ? 1 : 0;
}
