// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// notify_test.cpp - end to end test of a fusex mount and the notifications.
//
// Usage (as root, on a kernel with fusex):
//
//     fex-notify-test <empty_dir>
//
// Mounts an in-memory filesystem on <empty_dir>. The test changes the
// server's state directly, checks that the kernel keeps showing its cache,
// sends a notification, and checks that the kernel now shows the change.
// Prints "ok" or "FAIL" per check and exits non-zero on any FAIL. A check
// that hangs in the kernel ends the test through alarm().

#include <fex/fex.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using namespace std::chrono_literals;

namespace {

fex::NodeId to_node(std::uint64_t n) { return static_cast<fex::NodeId>(n); }

class MemFs final : public fex::Filesystem {
public:
    MemFs() {
        auto& root = nodes_[1];
        root.mode  = S_IFDIR | 0755;
        root.nlink = 2;
        root.nlookup = 1;
    }

    // ---- test side: change the server's state, bypassing the kernel ----

    std::uint64_t add_file(const std::string& name, std::string data) {
        std::lock_guard lk(mu_);
        const std::uint64_t id = next_id_++;
        auto& n = nodes_[id];
        n.mode  = S_IFREG | 0644;
        n.nlink = 1;
        n.data  = std::move(data);
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
        nodes_[id].data = std::move(data);
    }
    void set_mode(std::uint64_t id, std::uint16_t perm) {
        std::lock_guard lk(mu_);
        auto& n = nodes_[id];
        n.mode = static_cast<std::uint16_t>((n.mode & S_IFMT) | perm);
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

    bool wait_retrieve(std::uint64_t cookie, std::string& out) {
        std::unique_lock lk(mu_);
        if (!cv_.wait_for(lk, 10s, [&] { return retrieved_.count(cookie) != 0; }))
            return false;
        out = retrieved_[cookie];
        return true;
    }

    std::atomic<std::uint64_t> reads{0};
    std::atomic<std::uint64_t> lookups{0};

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
        n.atime   = in.stat.atime;
        n.mtime   = in.stat.mtime;
        n.ctime   = in.stat.ctime;
        nodes_[fex::to_underlying(parent)].children[std::string{in.name}] = id;
        fex::EntryOut e;
        e.nodeid = to_node(id);
        return e;
    }

    std::expected<void, fex::Errc>
    unlink(const fex::Context&, fex::NodeId parent, std::string_view name) override {
        std::lock_guard lk(mu_);
        auto& c = nodes_[fex::to_underlying(parent)].children;
        auto it = c.find(std::string{name});
        if (it == c.end())
            return std::unexpected{fex::Errc::no_such_file_or_directory};
        auto& n = nodes_[it->second];
        if (n.nlink)
            --n.nlink;
        c.erase(it);
        return {};
    }

    std::expected<void, fex::Errc>
    link(const fex::Context&, fex::NodeId oldnodeid, fex::NodeId newparent,
         std::string_view newname) override {
        std::lock_guard lk(mu_);
        ++nodes_[fex::to_underlying(oldnodeid)].nlink;
        nodes_[fex::to_underlying(newparent)].children[std::string{newname}] =
            fex::to_underlying(oldnodeid);
        return {};
    }

    std::expected<std::size_t, fex::Errc>
    read(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
         std::span<std::byte> out) override {
        ++reads;
        std::lock_guard lk(mu_);
        const auto& d = nodes_[fex::to_underlying(n)].data;
        if (off >= d.size())
            return std::size_t{0};
        const std::size_t len = std::min<std::size_t>(out.size(), d.size() - off);
        std::memcpy(out.data(), d.data() + off, len);
        return len;
    }

    std::expected<std::size_t, fex::Errc>
    write(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
          std::span<const std::byte> in) override {
        std::lock_guard lk(mu_);
        auto& d = nodes_[fex::to_underlying(n)].data;
        if (d.size() < off + in.size())
            d.resize(off + in.size());
        std::memcpy(d.data() + off, in.data(), in.size());
        return in.size();
    }

    std::expected<void, fex::Errc>
    readdir(const fex::Context&, fex::NodeId n, fex::FileHandle, std::uint64_t off,
            fex::DirentWriter& out) override {
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

    void retrieve_reply(const fex::Context&, fex::NodeId, std::uint64_t cookie,
                        std::uint64_t, std::span<const std::byte> data) noexcept override {
        {
            std::lock_guard lk(mu_);
            retrieved_[cookie] = std::string{
                reinterpret_cast<const char*>(data.data()), data.size()};
        }
        cv_.notify_all();
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
    std::condition_variable cv_;
    std::unordered_map<std::uint64_t, Node> nodes_;
    std::map<std::uint64_t, std::string> retrieved_;
    std::uint64_t next_id_ = 2;
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

std::span<const std::byte> bytes(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

// Keep the attributes invalid while the file grows: refreshing them must not
// shrink it to what the server has so far.
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
    bool closed = false;
    if (mounted) {
        const std::string path = mnt + "/dirty";
        const int fd = ::open(path.c_str(), O_CREAT | O_WRONLY, 0644);
        closed = fd >= 0 && ::write(fd, "dirty", 5) == 5 && ::close(fd) == 0;
        check(closed, "write without fsync");
    }

    session.stop();
    const bool stopped = run_result.wait_for(60s) == std::future_status::ready;
    check(stopped, "stop() ends the session");
    if (stopped) {
        runner.join();
        const auto ec = run_result.get();
        check(!ec, "clean end after stop()" + (ec ? ": " + ec.message() : std::string{}));
        if (closed)
            check(fs.data(fs.child("dirty")) == "dirty", "stop() wrote back the dirty data");
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
    check(::fsync(fd) == 0, "fsync");
    ::close(fd);
    const std::uint64_t id = fs.child("created");
    check(id != 0 && fs.data(id) == "abc", "the write reached the server");
    check(read_all(path) == "abc", "read back");
    check(::chmod(path.c_str(), 0600) == 0 && (fs.mode(id) & 07777) == 0600,
          "chmod reached the server (SETSTATX)");
    check(::unlink(path.c_str()) == 0 && !fs.has_child("created"), "unlink");
    check(!exists(path), "gone after unlink");
    check(eventually([&] { return fs.nlookup(id) == 0; }), "FORGET after unlink");
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
    test_append_under_invalidation(fs, session, mnt);
    test_delete_hard_link(fs, session, mnt);

    // ---- INVAL_INODE: attributes and data ------------------------------
    const std::string f = mnt + "/f";
    const std::uint64_t fid = fs.add_file("f", "hello");
    const fex::NodeId fnode = to_node(fid);
    check(read_all(f) == "hello", "read a file the server added");

    fs.set_data(fid, "hello world");
    check(size_of(f) == 5, "server change not visible before the notification");
    check_notify(session.notify_inval_inode(fnode), "INVAL_INODE");
    check(size_of(f) == 11, "new size after INVAL_INODE");
    check(read_all(f) == "hello world", "new data after INVAL_INODE");

    // ---- INVAL_INODE: attributes only keeps the cached data ------------
    std::uint64_t reads = fs.reads.load();
    fs.set_mode(fid, 0600);
    check(perm_of(f) == 0644, "mode change not visible before the notification");
    check_notify(session.notify_inval_inode(fnode, -1, 0), "INVAL_INODE, attributes only");
    check(perm_of(f) == 0600, "new mode after INVAL_INODE");
    check(read_all(f) == "hello world" && fs.reads.load() == reads,
          "data still comes from the cache");

    // ---- INVAL_INODE: a dirty folio is written, not lost ---------------
    int fd = ::open(f.c_str(), O_WRONLY);
    check(fd >= 0 && ::pwrite(fd, "D", 1, 0) == 1, "dirty a folio");
    if (fd >= 0)
        ::close(fd);
    check(fs.data(fid) == "hello world", "the dirty data is only in the cache");
    check_notify(session.notify_inval_inode(fnode), "INVAL_INODE on a dirty folio");
    check(fs.data(fid) == "Dello world", "the dirty data reached the server");

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

    // ---- STORE and RETRIEVE --------------------------------------------
    check(read_all(f) == "hello world", "cache the file");
    reads = fs.reads.load();
    check_notify(session.notify_store(fnode, 0, bytes("XYZ")), "STORE");
    check(read_all(f) == "XYZlo world" && fs.reads.load() == reads,
          "STORE changed the cache, without a READ");
    check(fs.data(fid) == "hello world", "STORE didn't touch the server's data");

    check_notify(session.notify_retrieve(fnode, 0, 3, 42), "RETRIEVE");
    std::string retrieved;
    check(fs.wait_retrieve(42, retrieved) && retrieved == "XYZ", "RETRIEVE reply has the cache");

    check_notify(session.notify_inval_inode(fnode), "drop the stored data");
    check(read_all(f) == "hello world", "the server's data is back");

    // ---- readdir cache -------------------------------------------------
    const auto has = [&](const std::string& name) {
        const auto names = list_dir(mnt);
        return std::find(names.begin(), names.end(), name) != names.end();
    };
    check(has("f"), "readdir");
    const std::uint64_t hid = fs.add_file("h", "H");
    check_notify(session.notify_inval_inode(fex::NodeId::root), "INVAL_INODE on the directory");
    check(has("h"), "readdir shows the new name");
    (void)hid;

    // ---- every lookup is counted, FORGET gives all of them back --------
    const std::uint64_t counted = fs.nlookup(fid);
    fd = ::open(f.c_str(), O_RDONLY);
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
    }

    test_stop_writes_back(mnt, before.st_dev);

    std::printf("%s\n", g_failures ? "FAILED" : "PASSED");
    return g_failures ? 1 : 0;
}
