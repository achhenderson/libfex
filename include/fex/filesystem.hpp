// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// fex/filesystem.hpp - the abstract interface every fusex daemon
// implements.
//
// Conventions:
//
// - Every callback runs on one of the session's io_uring worker threads.
//   Callbacks may execute concurrently across different nodeids and even
//   on the same nodeid — the kernel routes requests to the queue of the
//   CPU it runs on. Filesystem
//   implementations MUST be thread-safe; the dispatcher takes no lock
//   on behalf of the daemon.
//
// - Methods returning std::expected<T, std::errc> signal errors as the
//   `errc` part; the dispatcher translates these to negative errno on
//   the wire. Returning errc{0} for `expected<void,…>` is not allowed —
//   either fill the value (default-constructed structs are fine) or
//   return std::unexpected{std::errc::…}.
//
// - The default implementations all return std::errc::function_not_supported
//   so daemons override only what they need. The kernel doesn't open
//   regular files on the daemon: reads/writes/fallocate/fsync arrive with
//   fh=FileHandle{0}.
//
// - Caching file data is the daemon's business. Every read(2) and write(2)
//   arrives here, the kernel keeps no copy. Only mappings use its page cache:
//   a fault reads whole pages, and dirty pages come back as ordinary writes.
//   fsync() and syncfs() are how the kernel asks for durability.
//
// - The timestamps are the daemon's too. The kernel stamps nothing and takes
//   what statx() returns after an operation that changes them. So a write or
//   fallocate has to update mtime and ctime; a create, link, unlink or rename
//   those of the directories and the ctime of the object; an xattr change the
//   ctime; a read or readdir the atime, if the daemon keeps one. setstatx()
//   gets the times to set in its argument.

#pragma once

#include "types.hpp"
#include "reply.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <utility>

namespace fex {

class Filesystem {
public:
    virtual ~Filesystem() = default;

    // INIT negotiation. `info` arrives populated with what the kernel
    // announced; the daemon edits the to-kernel fields in place.
    // Returning an error aborts the mount.
    virtual std::expected<void, Errc> init(InitInfo& info) {
        (void)info;
        return {};
    }

    // Called once when Session::run() ends after a successful mount, with
    // all the workers stopped. The kernel has sent FUSE_DESTROY by then if
    // this is the end of an unmount.
    virtual void destroy() noexcept {}

    // FUSE_LOOKUP_ROOT (opcode 54): give the kernel the root inode's
    // identity at mount time. This is followed immediately by a
    // separate STATX on the returned nodeid. Convention: nodeid == 1.
    virtual std::expected<EntryOut, Errc> lookup_root(const Context& ctx) = 0;

    // FUSE_LOOKUPX (opcode 55): resolve `name` in `parent`. Return
    // EntryOut with `negative=true` to install a cached negative
    // dentry; the kernel will not retry until the daemon issues
    // FUSE_NOTIFY_INVAL_ENTRY (the fusex kernel does NOT honor the
    // entry_valid timeout — invalidation is daemon-driven).
    virtual std::expected<EntryOut, Errc>
    lookupx(const Context& ctx, NodeId parent, std::string_view name) = 0;

    // FUSE_FORGET (opcode 2). Sent when the kernel evicts an inode;
    // `nlookup` is the count to subtract from the daemon's per-inode
    // refcount, which tracks how many successful lookups/mkobjx replies
    // the kernel has observed minus how many FORGETs it has sent. When the
    // refcount reaches zero the daemon may drop its inode state. There are
    // no FORGETs for what the kernel still has at unmount.
    //
    // The dispatcher calls into the daemon synchronously on a ring worker
    // thread; keep the implementation cheap and noexcept.
    virtual void forget(NodeId nodeid, std::uint64_t nlookup) noexcept {
        (void)nodeid; (void)nlookup;
    }

    // BATCH_FORGET ships an array; default falls back to per-entry
    // forget() so a daemon only has to override one. Override directly
    // if you want to take the inode-map lock once for the whole batch.
    virtual void
    forget_multi(std::span<const std::pair<NodeId, std::uint64_t>> items) noexcept {
        for (auto& [n, nl] : items) forget(n, nl);
    }

    // FUSE_STATX (opcode 52): produce the full attribute set for nodeid.
    // The kernel ignores attr_valid timeouts in fusex. It asks again after
    // an operation of its own that changes attributes, and otherwise when
    // the server invalidates them with FUSE_NOTIFY_INVAL_INODE.
    virtual std::expected<StatxOut, Errc>
    statx(const Context& ctx, NodeId nodeid) = 0;

    // FUSE_SETSTATX (opcode 58): apply the masked attributes and reply
    // with the new full StatxOut (post-mutation). `fh` is the open
    // file's handle if the change came in through an open fd (e.g.
    // ftruncate, fchmod); FileHandle{0} otherwise.
    virtual std::expected<StatxOut, Errc>
    setstatx(const Context& ctx, NodeId nodeid, FileHandle fh,
             const SetStatxIn& in) {
        (void)ctx; (void)nodeid; (void)fh; (void)in;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_MKOBJX (opcode 56): create a new filesystem object in
    // `parent`. The kernel collapses CREATE/MKDIR/MKNOD/SYMLINK/TMPFILE
    // into this single opcode; inspect `in.stat.mode & S_IFMT` and
    // `in.flags & kMkobjxTmpfile` to decide the kind. For S_IFLNK,
    // `in.link_target` carries the link body. For tmpfile, `in.name`
    // is empty.
    virtual std::expected<EntryOut, Errc>
    mkobjx(const Context& ctx, NodeId parent, const MkobjxIn& in) {
        (void)ctx; (void)parent; (void)in;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_UNLINK / FUSE_RMDIR (opcodes 10 / 11). The kernel
    // distinguishes them by opcode; the daemon doesn't need to.
    virtual std::expected<void, Errc>
    unlink(const Context& ctx, NodeId parent, std::string_view name) {
        (void)ctx; (void)parent; (void)name;
        return std::unexpected{Errc::function_not_supported};
    }
    virtual std::expected<void, Errc>
    rmdir(const Context& ctx, NodeId parent, std::string_view name) {
        return unlink(ctx, parent, name);
    }

    // FUSE_RENAME2 (opcode 45). `flags` is a RENAME_* set from
    // <linux/fs.h>: NOREPLACE / EXCHANGE / WHITEOUT.
    virtual std::expected<void, Errc>
    rename(const Context& ctx,
           NodeId olddir, std::string_view oldname,
           NodeId newdir, std::string_view newname,
           std::uint32_t flags) {
        (void)ctx; (void)olddir; (void)oldname;
        (void)newdir; (void)newname; (void)flags;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_LINK (opcode 13). The fusex kernel expects an EMPTY reply
    // (no fuse_entry_out / fuse_entryx_out payload), so this signature
    // returns expected<void>; the kernel re-issues STATX afterward.
    virtual std::expected<void, Errc>
    link(const Context& ctx, NodeId oldnodeid,
         NodeId newparent, std::string_view newname) {
        (void)ctx; (void)oldnodeid; (void)newparent; (void)newname;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_READLINK (opcode 5). Return the link body. Note: max length
    // is bounded by what the kernel asked for (one page - 1).
    virtual std::expected<std::string, Errc>
    readlink(const Context& ctx, NodeId nodeid) {
        (void)ctx; (void)nodeid;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_OPEN (opcode 14) / FUSE_RELEASE (opcode 18). The fusex kernel
    // doesn't send these today.
    virtual std::expected<OpenOut, Errc>
    open(const Context& ctx, NodeId nodeid, std::uint32_t flags) {
        (void)ctx; (void)nodeid; (void)flags;
        return OpenOut{};  // fh=0, open_flags=0
    }

    virtual std::expected<void, Errc>
    release(const Context& ctx, NodeId nodeid, FileHandle fh,
            std::uint32_t flags) {
        (void)ctx; (void)nodeid; (void)fh; (void)flags;
        return {};
    }

    // FUSE_READ (opcode 15): a read(2), or a fault reading a mapped page.
    // Fill `out` with up to `out.size()` bytes starting at `offset`. Return
    // the number actually written. A short count ends the read(2) there,
    // the rest of a mapped page reads as zeros. `fh` is 0.
    virtual std::expected<std::size_t, Errc>
    read(const Context& ctx, NodeId nodeid, FileHandle fh,
         std::uint64_t offset, std::span<std::byte> out) {
        (void)ctx; (void)nodeid; (void)fh; (void)offset; (void)out;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_WRITE (opcode 16): a write(2), or the writeback of a dirty mapped
    // page, which is a whole page and comes with uid and gid 0. Consume `in`
    // starting at `offset`. Return the number of bytes accepted. A short
    // count ends the write(2) there and fails the writeback; accepting
    // nothing is -EIO for the caller. `fh` is 0.
    virtual std::expected<std::size_t, Errc>
    write(const Context& ctx, NodeId nodeid, FileHandle fh,
          std::uint64_t offset, std::span<const std::byte> in) {
        (void)ctx; (void)nodeid; (void)fh; (void)offset; (void)in;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_FALLOCATE (opcode 43). The fusex kernel filters modes to
    // KEEP_SIZE|PUNCH_HOLE|ZERO_RANGE before forwarding.
    virtual std::expected<void, Errc>
    fallocate(const Context& ctx, NodeId nodeid, FileHandle fh,
              std::uint32_t mode, std::uint64_t offset, std::uint64_t length) {
        (void)ctx; (void)nodeid; (void)fh;
        (void)mode; (void)offset; (void)length;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_FSYNC (opcode 20): make what the daemon has for `nodeid` durable,
    // with `datasync` only what it takes to read the data back. fsync(2),
    // msync(2) and O_SYNC writes end up here, after the dirty mapped pages
    // were written. The error goes to the caller. Without an implementation
    // those calls succeed and promise nothing. `fh` is 0.
    virtual std::expected<void, Errc>
    fsync(const Context& ctx, NodeId nodeid, FileHandle fh, bool datasync) {
        (void)ctx; (void)nodeid; (void)fh; (void)datasync;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_FSYNCDIR (opcode 30): the same for a directory, `fh` is what
    // opendir() returned.
    virtual std::expected<void, Errc>
    fsyncdir(const Context& ctx, NodeId nodeid, FileHandle fh, bool datasync) {
        (void)ctx; (void)nodeid; (void)fh; (void)datasync;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_SYNCFS (opcode 50): make everything durable. sync(2), syncfs(2) and
    // an unmount end up here, after the dirty mapped pages were written.
    virtual std::expected<void, Errc>
    syncfs(const Context& ctx) {
        (void)ctx;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_STATFS (opcode 17). No nodeid context needed (statfs on
    // mount root), but the kernel still passes it for consistency.
    virtual std::expected<StatfsOut, Errc>
    statfs(const Context& ctx, NodeId nodeid) {
        (void)ctx; (void)nodeid;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_OPENDIR (opcode 27) / FUSE_RELEASEDIR (opcode 29). The fusex
    // kernel only uses the fh of the reply.
    virtual std::expected<OpenOut, Errc>
    opendir(const Context& ctx, NodeId nodeid) {
        (void)ctx; (void)nodeid;
        return OpenOut{};  // fh=0, open_flags=0
    }

    virtual std::expected<void, Errc>
    releasedir(const Context& ctx, NodeId nodeid, FileHandle fh) {
        (void)ctx; (void)nodeid; (void)fh;
        return {};
    }

    // FUSE_READDIR (opcode 28). Pack as many entries as fit. `offset`
    // is the value returned in DirentWriter::add(off=...) for the
    // previous entry, or zero for the first call. The kernel doesn't
    // cache directories: a new name shows up in the next readdir(3).
    virtual std::expected<void, Errc>
    readdir(const Context& ctx, NodeId nodeid, FileHandle fh,
            std::uint64_t offset, DirentWriter& out) {
        (void)ctx; (void)nodeid; (void)fh; (void)offset; (void)out;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_GETXATTR (opcode 22). If `out.empty()`, the kernel is asking
    // for the size only - return the would-be byte count. Otherwise
    // fill `out` and return the count written; -ERANGE if too small.
    virtual std::expected<std::size_t, Errc>
    getxattr(const Context& ctx, NodeId nodeid,
             std::string_view name, std::span<std::byte> out) {
        (void)ctx; (void)nodeid; (void)name; (void)out;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_SETXATTR (opcode 21).
    virtual std::expected<void, Errc>
    setxattr(const Context& ctx, NodeId nodeid,
             std::string_view name, std::span<const std::byte> value,
             std::uint32_t flags) {
        (void)ctx; (void)nodeid; (void)name; (void)value; (void)flags;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_LISTXATTR (opcode 23). Same size-vs-fill convention as
    // getxattr; the buffer is a sequence of NUL-terminated names.
    virtual std::expected<std::size_t, Errc>
    listxattr(const Context& ctx, NodeId nodeid, std::span<std::byte> out) {
        (void)ctx; (void)nodeid; (void)out;
        return std::unexpected{Errc::function_not_supported};
    }

    // FUSE_REMOVEXATTR (opcode 24).
    virtual std::expected<void, Errc>
    removexattr(const Context& ctx, NodeId nodeid, std::string_view name) {
        (void)ctx; (void)nodeid; (void)name;
        return std::unexpected{Errc::function_not_supported};
    }
};

}  // namespace fex
