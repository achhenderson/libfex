// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Per-opcode handlers and the top-level dispatch switch.
//
// Each handler is a Session::Impl member taking the in-header, a pointer
// to the in_args bytes (laid out contiguously by the worker), the
// remaining length, and a Replier to fill. No I/O happens here —
// handlers are pure CPU work; the io_uring transport in uring_worker.cpp
// ships the reply blobs back to the kernel.

#include "session_impl.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

namespace fex {

namespace {

// -----------------------------------------------------------------------
// statx wire <-> StatxOut conversion. File-local: only the handlers in
// this TU need them.
// -----------------------------------------------------------------------

void pack_statx(const StatxOut& src, std::chrono::nanoseconds attr_valid,
                ::fuse_statx_out& out) noexcept
{
    std::memset(&out, 0, sizeof(out));
    std::uint32_t nsec = 0;
    split_duration(attr_valid, out.attr_valid, nsec);
    out.attr_valid_nsec = nsec;

    auto& s = out.stat;
    s.mask            = src.mask;
    s.blksize         = src.blksize;
    s.attributes      = src.attributes;
    s.nlink           = src.nlink;
    s.uid             = src.uid;
    s.gid             = src.gid;
    s.mode            = src.mode;
    s.ino             = src.ino;
    s.size            = src.size;
    s.blocks          = src.blocks;
    s.attributes_mask = src.attributes_mask;
    s.atime.tv_sec    = src.atime.sec;
    s.atime.tv_nsec   = src.atime.nsec;
    s.btime.tv_sec    = src.btime.sec;
    s.btime.tv_nsec   = src.btime.nsec;
    s.ctime.tv_sec    = src.ctime.sec;
    s.ctime.tv_nsec   = src.ctime.nsec;
    s.mtime.tv_sec    = src.mtime.sec;
    s.mtime.tv_nsec   = src.mtime.nsec;
    s.rdev_major      = src.rdev_major;
    s.rdev_minor      = src.rdev_minor;
    s.dev_major       = src.dev_major;
    s.dev_minor       = src.dev_minor;
}

// Same FEX_DEBUG gate the passthrough example uses, evaluated once.
bool debug_enabled() noexcept {
    static const bool on = [] {
        const char* e = std::getenv("FEX_DEBUG");
        return e && *e && *e != '0';
    }();
    return on;
}

const char* opcode_name(std::uint32_t op) noexcept {
    switch (op) {
    case FUSE_LOOKUP:        return "LOOKUP";
    case FUSE_FORGET:        return "FORGET";
    case FUSE_GETATTR:       return "GETATTR";
    case FUSE_SETATTR:       return "SETATTR";
    case FUSE_READLINK:      return "READLINK";
    case FUSE_SYMLINK:       return "SYMLINK";
    case FUSE_MKNOD:         return "MKNOD";
    case FUSE_MKDIR:         return "MKDIR";
    case FUSE_UNLINK:        return "UNLINK";
    case FUSE_RMDIR:         return "RMDIR";
    case FUSE_RENAME:        return "RENAME";
    case FUSE_LINK:          return "LINK";
    case FUSE_OPEN:          return "OPEN";
    case FUSE_READ:          return "READ";
    case FUSE_WRITE:         return "WRITE";
    case FUSE_STATFS:        return "STATFS";
    case FUSE_RELEASE:       return "RELEASE";
    case FUSE_FSYNC:         return "FSYNC";
    case FUSE_SETXATTR:      return "SETXATTR";
    case FUSE_GETXATTR:      return "GETXATTR";
    case FUSE_LISTXATTR:     return "LISTXATTR";
    case FUSE_REMOVEXATTR:   return "REMOVEXATTR";
    case FUSE_FLUSH:         return "FLUSH";
    case FUSE_INIT:          return "INIT";
    case FUSE_OPENDIR:       return "OPENDIR";
    case FUSE_READDIR:       return "READDIR";
    case FUSE_RELEASEDIR:    return "RELEASEDIR";
    case FUSE_FSYNCDIR:      return "FSYNCDIR";
    case FUSE_FALLOCATE:     return "FALLOCATE";
    case FUSE_RENAME2:       return "RENAME2";
    case FUSE_STATX:         return "STATX";
    case FUSE_LOOKUP_ROOT:   return "LOOKUP_ROOT";
    case FUSE_LOOKUPX:       return "LOOKUPX";
    case FUSE_MKOBJX:        return "MKOBJX";
    case FUSE_SETSTATX:      return "SETSTATX";
    case FUSE_COMPOUND:      return "COMPOUND";
    default:                 return "?";
    }
}

void unpack_statx(const ::fuse_statx& w, SetStatxIn& dst) noexcept {
    dst.mask = w.mask;
    dst.mode = w.mode;
    dst.uid  = w.uid;
    dst.gid  = w.gid;
    dst.size = w.size;
    dst.atime = {w.atime.tv_sec, w.atime.tv_nsec};
    dst.ctime = {w.ctime.tv_sec, w.ctime.tv_nsec};
    dst.mtime = {w.mtime.tv_sec, w.mtime.tv_nsec};
}

}  // anonymous

// -----------------------------------------------------------------------
// Per-opcode handlers
// -----------------------------------------------------------------------

void Session::Impl::handle_init(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_init_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    const std::uint64_t kernel_flags =
        static_cast<std::uint64_t>(in->flags)
      | (static_cast<std::uint64_t>(in->flags2) << 32);

    // We require the kernel to advertise FUSE_OVER_IO_URING; the
    // session has no read()/write() runtime path. If the kernel
    // module on this host doesn't support it, we can't proceed.
    if ((kernel_flags & FUSE_OVER_IO_URING) == 0) {
        reply_error(r, Errc::operation_not_supported);
        return;
    }

    InitInfo info;
    info.kernel_major   = in->major;
    info.kernel_minor   = in->minor;
    info.kernel_flags   = kernel_flags;
    info.max_readahead  = in->max_readahead;

    // Cap max_write / max_pages so a single request fits in one ring
    // entry's payload buffer. We negotiate this with the kernel so it
    // never sends a request larger than what a ring slot can hold.
    info.max_write = std::min<std::uint32_t>(
        info.max_write,
        static_cast<std::uint32_t>(opts.uring_payload_bytes));
    info.max_pages = static_cast<std::uint16_t>(std::min<std::size_t>(
        info.max_pages,
        (opts.uring_payload_bytes + 4095u) / 4096u));

    // Sane defaults: advertise EXT (required by fusex), enable URING,
    // request PARALLEL_DIROPS for concurrent lookups, and ack
    // WRITEBACK_CACHE so the kernel can update mtime/ctime/size
    // locally and batch flushes through writepages.
    info.flags = FUSE_INIT_EXT | FUSE_MAX_PAGES | FUSE_PARALLEL_DIROPS
               | FUSE_OVER_IO_URING | FUSE_WRITEBACK_CACHE;

    if (auto rc = fs->init(info); !rc) { reply_error(r, rc.error()); return; }

    // Keep FUSE_OVER_IO_URING set even if the filesystem cleared it;
    // the session has no other transport once bootstrap ends.
    info.flags |= FUSE_OVER_IO_URING;

    if (info.kernel_major != FUSE_KERNEL_VERSION) {
        // Major mismatch: per the FUSE handshake we reply with our
        // version and the kernel will either re-INIT or give up.
        ::fuse_init_out out{};
        out.major = FUSE_KERNEL_VERSION;
        reply_pod(r, out);
        return;
    }

    ::fuse_init_out out{};
    out.major          = FUSE_KERNEL_VERSION;
    out.minor          = std::min<std::uint32_t>(in->minor, FUSE_KERNEL_MINOR_VERSION);
    out.max_readahead  = in->max_readahead;
    out.flags          = static_cast<std::uint32_t>(info.flags & 0xffffffffu);
    out.flags2         = static_cast<std::uint32_t>(info.flags >> 32);
    out.max_background       = 64;
    out.congestion_threshold = 48;
    out.max_write      = info.max_write;
    out.time_gran      = info.time_gran;
    out.max_pages      = info.max_pages;

    init_done = true;
    reply_pod(r, out);
}

void Session::Impl::handle_lookup_root(
    const ::fuse_in_header& h, const std::byte*, std::size_t, Replier& r)
{
    auto rv = fs->lookup_root(make_ctx(h));
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_entryx_out out{};
    out.nodeid           = to_underlying(rv->nodeid);
    std::uint64_t sec; std::uint32_t nsec;
    split_duration(rv->entry_valid, sec, nsec);
    out.entry_valid      = sec;
    out.entry_valid_nsec = nsec;
    out.flags            = rv->negative ? FUSE_ENTRYX_NEGATIVE : 0u;
    reply_pod(r, out);
}

void Session::Impl::handle_lookupx(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Only in_arg: NUL-terminated name (kernel uses ADD_IN_ARG_ZERO for
    // an empty leading arg, so the name starts at the head of body).
    if (body_len < 1u) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const char* name = reinterpret_cast<const char*>(body);
    const std::size_t nlen = ::strnlen(name, body_len);
    if (nlen == body_len) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->lookupx(make_ctx(h), static_cast<NodeId>(h.nodeid),
                          std::string_view{name, nlen});
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_entryx_out out{};
    out.nodeid           = to_underlying(rv->nodeid);
    std::uint64_t sec; std::uint32_t nsec;
    split_duration(rv->entry_valid, sec, nsec);
    out.entry_valid      = sec;
    out.entry_valid_nsec = nsec;
    out.flags            = rv->negative ? FUSE_ENTRYX_NEGATIVE : 0u;
    reply_pod(r, out);
}

void Session::Impl::handle_forget(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Single-inode FORGET. in_args[0] = fuse_forget_in (8 B, fits in
    // op_in). The kernel does not wait for a reply — see the empty-reply
    // note in dispatch(). We still produce reply_ok() so the io_uring
    // worker re-arms the slot via COMMIT_AND_FETCH.
    const auto* in = in_arg<::fuse_forget_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    fs->forget(static_cast<NodeId>(h.nodeid), in->nlookup);
    reply_ok(r);
}

void Session::Impl::handle_batch_forget(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // in_args[0] = fuse_batch_forget_in { count, dummy } (op_in).
    // in_args[1] = count × fuse_forget_one { nodeid, nlookup } (payload).
    const auto* in = in_arg<::fuse_batch_forget_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    const std::uint32_t count = in->count;
    constexpr std::size_t off  = sizeof(::fuse_batch_forget_in);
    const std::size_t need = static_cast<std::size_t>(count) *
                             sizeof(::fuse_forget_one);
    if (body_len < off + need) {
        // Truncated batch. There is no error reply for BATCH_FORGET on
        // the wire either; just bail without calling the FS.
        reply_ok(r); return;
    }
    const auto* items = reinterpret_cast<const ::fuse_forget_one*>(body + off);

    // Repack into the public (NodeId, nlookup) shape so daemons don't
    // see wire types. The vector is bounded by `count`; for typical
    // batch sizes (a few dozen) the allocation cost is negligible
    // compared to whatever the daemon does with each entry.
    std::vector<std::pair<NodeId, std::uint64_t>> repacked;
    repacked.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        repacked.emplace_back(static_cast<NodeId>(items[i].nodeid),
                              items[i].nlookup);
    }
    fs->forget_multi(repacked);
    reply_ok(r);
}

void Session::Impl::handle_statx(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // We don't currently use the in-arg (mask/flags). Validate size.
    const auto* in = in_arg<::fuse_statx_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }
    (void)in;

    auto rv = fs->statx(make_ctx(h), static_cast<NodeId>(h.nodeid));
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_statx_out out;
    pack_statx(*rv, std::chrono::seconds(1), out);
    reply_pod(r, out);
}

void Session::Impl::handle_setstatx(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // The kernel splits fuse_setstatx_in around offsetof(stat):
    //   in_args[0] = control header (fh, flags, reserved) — 16 B
    //   in_args[1] = struct fuse_statx
    // The C struct still embeds .stat but on the wire .stat is a
    // separate in_arg, so we read it past the control header.
    constexpr std::size_t stat_off = offsetof(::fuse_setstatx_in, stat);
    const auto* in = in_arg<::fuse_setstatx_in>(h, body, body_len);
    if (!in || body_len < stat_off + sizeof(::fuse_statx)) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* sx = reinterpret_cast<const ::fuse_statx*>(body + stat_off);

    SetStatxIn s;
    s.mask = sx->mask;
    unpack_statx(*sx, s);

    auto rv = fs->setstatx(make_ctx(h), static_cast<NodeId>(h.nodeid),
                           static_cast<FileHandle>(in->fh), s);
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_statx_out out;
    pack_statx(*rv, std::chrono::seconds(1), out);
    reply_pod(r, out);
}

void Session::Impl::handle_mkobjx(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [namesize/flags/spare][struct fuse_statx][name+NUL][link_body?]
    // (link_body present only for S_IFLNK).
    constexpr std::size_t hdr_sz   = offsetof(::fuse_mkobjx_in, stat);
    constexpr std::size_t stat_off = hdr_sz;
    constexpr std::size_t name_off = stat_off + sizeof(::fuse_statx);
    const std::size_t ext = std::size_t{h.total_extlen} * 8u;
    if (body_len < ext + name_off) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* in = reinterpret_cast<const ::fuse_mkobjx_in*>(body + ext);
    const auto* sx = reinterpret_cast<const ::fuse_statx*>(body + stat_off);

    if (body_len < name_off + in->namesize) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const char* name_ptr = reinterpret_cast<const char*>(body + name_off);
    // namesize includes the trailing NUL.
    std::size_t name_len = in->namesize ? (in->namesize - 1u) : 0u;

    std::string_view link_body;
    if ((sx->mode & 0xf000u) == 0xa000u /* S_IFLNK */) {
        const std::size_t after = name_off + in->namesize;
        if (body_len > after) {
            const char* lp = reinterpret_cast<const char*>(body + after);
            const std::size_t lavail = body_len - after;
            const std::size_t llen   = ::strnlen(lp, lavail);
            link_body = std::string_view{lp, llen};
        }
    }

    MkobjxIn mi;
    mi.flags = in->flags;
    mi.name  = std::string_view{name_ptr, name_len};
    mi.link_target = link_body;
    // Copy the requested stat (kernel fills mode/uid/gid/rdev/btime).
    mi.stat.mode       = sx->mode;
    mi.stat.uid        = sx->uid;
    mi.stat.gid        = sx->gid;
    mi.stat.rdev_major = sx->rdev_major;
    mi.stat.rdev_minor = sx->rdev_minor;
    mi.stat.mask       = sx->mask;
    mi.stat.atime      = {sx->atime.tv_sec, sx->atime.tv_nsec};
    mi.stat.btime      = {sx->btime.tv_sec, sx->btime.tv_nsec};
    mi.stat.ctime      = {sx->ctime.tv_sec, sx->ctime.tv_nsec};
    mi.stat.mtime      = {sx->mtime.tv_sec, sx->mtime.tv_nsec};

    auto rv = fs->mkobjx(make_ctx(h), static_cast<NodeId>(h.nodeid), mi);
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_entryx_out out{};
    out.nodeid           = to_underlying(rv->nodeid);
    std::uint64_t sec; std::uint32_t nsec;
    split_duration(rv->entry_valid, sec, nsec);
    out.entry_valid      = sec;
    out.entry_valid_nsec = nsec;
    out.flags            = 0;
    reply_pod(r, out);
}

void Session::Impl::handle_unlink(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r, bool is_rmdir)
{
    // Kernel sends an empty in_args[0] and the name as in_args[1].
    if (body_len < 1u) { reply_error(r, Errc::invalid_argument); return; }
    const char* name = reinterpret_cast<const char*>(body);
    const std::size_t nlen = ::strnlen(name, body_len);
    if (nlen == body_len) { reply_error(r, Errc::invalid_argument); return; }

    const auto sv = std::string_view{name, nlen};
    auto rv = is_rmdir
        ? fs->rmdir(make_ctx(h), static_cast<NodeId>(h.nodeid), sv)
        : fs->unlink(make_ctx(h), static_cast<NodeId>(h.nodeid), sv);
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_rename2(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [fuse_rename2_in][old_name + NUL + new_name + NUL]
    const std::size_t ext   = std::size_t{h.total_extlen} * 8u;
    const std::size_t names_off = ext + sizeof(::fuse_rename2_in);
    if (body_len < names_off + 2u) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* in = reinterpret_cast<const ::fuse_rename2_in*>(body + ext);
    const char* names = reinterpret_cast<const char*>(body + names_off);
    const std::size_t avail = body_len - names_off;

    const std::size_t olen = ::strnlen(names, avail);
    if (olen == avail) { reply_error(r, Errc::invalid_argument); return; }
    const char* second = names + olen + 1u;
    const std::size_t remain = avail - olen - 1u;
    const std::size_t nlen = ::strnlen(second, remain);
    if (nlen == remain) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->rename(
        make_ctx(h),
        static_cast<NodeId>(h.nodeid), std::string_view{names, olen},
        static_cast<NodeId>(in->newdir), std::string_view{second, nlen},
        in->flags);
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_link(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [fuse_link_in][name + NUL]
    const std::size_t ext      = std::size_t{h.total_extlen} * 8u;
    const std::size_t name_off = ext + sizeof(::fuse_link_in);
    if (body_len < name_off + 1u) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* in = reinterpret_cast<const ::fuse_link_in*>(body + ext);
    const char* name = reinterpret_cast<const char*>(body + name_off);
    const std::size_t avail = body_len - name_off;
    const std::size_t nlen = ::strnlen(name, avail);
    if (nlen == avail) { reply_error(r, Errc::invalid_argument); return; }

    // The kernel module expects an empty reply (no fuse_entry_out) for
    // FUSE_LINK and follows up with STATX. See fusex-review.md item 5b.
    auto rv = fs->link(make_ctx(h),
                       static_cast<NodeId>(in->oldnodeid),
                       static_cast<NodeId>(h.nodeid),
                       std::string_view{name, nlen});
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_open(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_open_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->open(make_ctx(h), static_cast<NodeId>(h.nodeid), in->flags);
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_open_out out{};
    out.fh         = to_underlying(rv->fh);
    out.open_flags = rv->open_flags;
    reply_pod(r, out);
}

void Session::Impl::handle_release(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_release_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->release(make_ctx(h), static_cast<NodeId>(h.nodeid),
                          static_cast<FileHandle>(in->fh), in->flags);
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_read(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_read_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    // Stream the read directly into the reply buffer. The Replier
    // capacity is sized to the per-entry payload area, so any size
    // the kernel asked for that the daemon advertised (max_write /
    // max_pages negotiation in INIT) fits without a second copy.
    const std::size_t want = std::min<std::size_t>(in->size, r.cap);
    auto rv = fs->read(make_ctx(h), static_cast<NodeId>(h.nodeid),
                       static_cast<FileHandle>(in->fh),
                       in->offset,
                       std::span<std::byte>{r.out, want});
    if (!rv) { reply_error(r, rv.error()); return; }
    r.neg_err = 0;
    r.len     = std::min(*rv, want);
}

void Session::Impl::handle_write(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [fuse_write_in][data]
    const std::size_t ext      = std::size_t{h.total_extlen} * 8u;
    const std::size_t data_off = ext + sizeof(::fuse_write_in);
    if (body_len < data_off) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* in = reinterpret_cast<const ::fuse_write_in*>(body + ext);
    if (body_len - data_off < in->size) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const std::byte* data = body + data_off;
    auto rv = fs->write(make_ctx(h), static_cast<NodeId>(h.nodeid),
                        static_cast<FileHandle>(in->fh),
                        in->offset,
                        std::span<const std::byte>{data, in->size});
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_write_out out{};
    out.size = static_cast<std::uint32_t>(*rv);
    reply_pod(r, out);
}

void Session::Impl::handle_readlink(
    const ::fuse_in_header& h, const std::byte*, std::size_t, Replier& r)
{
    auto rv = fs->readlink(make_ctx(h), static_cast<NodeId>(h.nodeid));
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_payload(r, std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(rv->data()), rv->size()});
}

void Session::Impl::handle_statfs(
    const ::fuse_in_header& h, const std::byte*, std::size_t, Replier& r)
{
    auto rv = fs->statfs(make_ctx(h), static_cast<NodeId>(h.nodeid));
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_statfs_out out{};
    out.st.blocks  = rv->blocks;
    out.st.bfree   = rv->bfree;
    out.st.bavail  = rv->bavail;
    out.st.files   = rv->files;
    out.st.ffree   = rv->ffree;
    out.st.bsize   = rv->bsize;
    out.st.namelen = rv->namelen;
    out.st.frsize  = rv->frsize;
    reply_pod(r, out);
}

void Session::Impl::handle_fallocate(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_fallocate_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->fallocate(make_ctx(h), static_cast<NodeId>(h.nodeid),
                            static_cast<FileHandle>(in->fh),
                            in->mode, in->offset, in->length);
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_opendir(
    const ::fuse_in_header& h, const std::byte*, std::size_t, Replier& r)
{
    auto rv = fs->opendir(make_ctx(h), static_cast<NodeId>(h.nodeid));
    if (!rv) { reply_error(r, rv.error()); return; }

    ::fuse_open_out out{};
    out.fh         = to_underlying(rv->fh);
    out.open_flags = rv->open_flags | FOPEN_CACHE_DIR;  // kernel forces it
    // backing_id is zero by value-init; we don't use FOPEN_PASSTHROUGH,
    // and the field is absent on pre-6.10 <linux/fuse.h>.
    reply_pod(r, out);
}

void Session::Impl::handle_releasedir(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_release_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->releasedir(make_ctx(h), static_cast<NodeId>(h.nodeid),
                             static_cast<FileHandle>(in->fh));
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_readdir(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_read_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    // Pack entries directly into the reply buffer, capped at the
    // smaller of (kernel-requested size, Replier capacity).
    const std::size_t cap = std::min<std::size_t>(in->size, r.cap);
    DirentWriter w{std::span<std::byte>{r.out, cap}};

    auto rv = fs->readdir(make_ctx(h), static_cast<NodeId>(h.nodeid),
                          static_cast<FileHandle>(in->fh),
                          in->offset, w);
    if (!rv) { reply_error(r, rv.error()); return; }
    r.neg_err = 0;
    r.len     = w.bytes_written();
}

void Session::Impl::handle_getxattr(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [fuse_getxattr_in][name + NUL]
    const std::size_t ext      = std::size_t{h.total_extlen} * 8u;
    const std::size_t name_off = ext + sizeof(::fuse_getxattr_in);
    if (body_len < name_off + 1u) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* in = reinterpret_cast<const ::fuse_getxattr_in*>(body + ext);
    const char* name = reinterpret_cast<const char*>(body + name_off);
    const std::size_t avail = body_len - name_off;
    const std::size_t nlen = ::strnlen(name, avail);
    if (nlen == avail) { reply_error(r, Errc::invalid_argument); return; }

    if (in->size == 0) {
        // Size query.
        auto rv = fs->getxattr(make_ctx(h), static_cast<NodeId>(h.nodeid),
                               std::string_view{name, nlen}, {});
        if (!rv) { reply_error(r, rv.error()); return; }
        ::fuse_getxattr_out out{};
        out.size = static_cast<std::uint32_t>(*rv);
        reply_pod(r, out);
        return;
    }

    const std::size_t cap = std::min<std::size_t>(in->size, r.cap);
    auto rv = fs->getxattr(make_ctx(h), static_cast<NodeId>(h.nodeid),
                           std::string_view{name, nlen},
                           std::span<std::byte>{r.out, cap});
    if (!rv) { reply_error(r, rv.error()); return; }
    r.neg_err = 0;
    r.len     = std::min(*rv, cap);
}

void Session::Impl::handle_setxattr(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [fuse_setxattr_in][name + NUL][value]
    const std::size_t ext      = std::size_t{h.total_extlen} * 8u;
    const std::size_t name_off = ext + sizeof(::fuse_setxattr_in);
    if (body_len < name_off + 1u) {
        reply_error(r, Errc::invalid_argument); return;
    }
    const auto* in = reinterpret_cast<const ::fuse_setxattr_in*>(body + ext);
    const char* name = reinterpret_cast<const char*>(body + name_off);
    const std::size_t avail = body_len - name_off;
    const std::size_t nlen = ::strnlen(name, avail);
    if (nlen == avail) { reply_error(r, Errc::invalid_argument); return; }

    const std::size_t after = name_off + nlen + 1u;
    if (body_len < after + in->size) {
        reply_error(r, Errc::invalid_argument); return;
    }
    auto rv = fs->setxattr(make_ctx(h), static_cast<NodeId>(h.nodeid),
                           std::string_view{name, nlen},
                           std::span<const std::byte>{body + after, in->size},
                           in->flags);
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_listxattr(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const auto* in = in_arg<::fuse_getxattr_in>(h, body, body_len);
    if (!in) { reply_error(r, Errc::invalid_argument); return; }

    if (in->size == 0) {
        auto rv = fs->listxattr(make_ctx(h), static_cast<NodeId>(h.nodeid), {});
        if (!rv) { reply_error(r, rv.error()); return; }
        ::fuse_getxattr_out out{};
        out.size = static_cast<std::uint32_t>(*rv);
        reply_pod(r, out);
        return;
    }
    const std::size_t cap = std::min<std::size_t>(in->size, r.cap);
    auto rv = fs->listxattr(make_ctx(h), static_cast<NodeId>(h.nodeid),
                            std::span<std::byte>{r.out, cap});
    if (!rv) { reply_error(r, rv.error()); return; }
    r.neg_err = 0;
    r.len     = std::min(*rv, cap);
}

void Session::Impl::handle_removexattr(
    const ::fuse_in_header& h, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    const std::size_t ext = std::size_t{h.total_extlen} * 8u;
    const char* name = reinterpret_cast<const char*>(body + ext);
    const std::size_t avail = body_len - ext;
    const std::size_t nlen = ::strnlen(name, avail);
    if (nlen == avail) { reply_error(r, Errc::invalid_argument); return; }

    auto rv = fs->removexattr(make_ctx(h), static_cast<NodeId>(h.nodeid),
                              std::string_view{name, nlen});
    if (!rv) { reply_error(r, rv.error()); return; }
    reply_ok(r);
}

void Session::Impl::handle_compound(
    const ::fuse_in_header&, const std::byte* body, std::size_t body_len,
    Replier& r)
{
    // Wire: [fuse_compound_in] {[fuse_compound_req_in][fuse_in_header]
    // [in_args...]}*. The reply mirrors it: [fuse_compound_out]
    // {[fuse_out_header][out_args...]}*. The top-level fuse_out_header
    // is written by the worker around what we put in r.out.
    if (body_len < sizeof(::fuse_compound_in) ||
        r.cap   < sizeof(::fuse_compound_out)) {
        reply_error(r, Errc::invalid_argument); return;
    }
    std::memset(r.out, 0, sizeof(::fuse_compound_out));

    const std::byte* p       = body + sizeof(::fuse_compound_in);
    const std::byte* end     = body + body_len;
    std::byte*       out_p   = r.out + sizeof(::fuse_compound_out);
    std::byte* const out_end = r.out + r.cap;

    // Per-subop produced nodeids, indexed by subop position. Threaded
    // into dependent subops' fuse_in_header.nodeid before dispatch -
    // mirrors fuse_compound_propagate_nodeid() in the kernel's legacy
    // fallback path, which doesn't run when the daemon (us) handles
    // compounds itself.
    std::vector<std::uint64_t> produced;

    const bool log = debug_enabled();
    if (log) std::fputs("[fex] compound [", stderr);

    while (p < end) {
        const std::size_t hdrs = sizeof(::fuse_compound_req_in) +
                                 sizeof(::fuse_in_header);
        if (static_cast<std::size_t>(end - p) < hdrs ||
            out_p + sizeof(::fuse_out_header) > out_end) {
            reply_error(r, Errc::invalid_argument); return;
        }
        ::fuse_compound_req_in sub_req;
        std::memcpy(&sub_req, p, sizeof(sub_req));
        p += sizeof(::fuse_compound_req_in);
        ::fuse_in_header sub_h;
        std::memcpy(&sub_h, p, sizeof(sub_h));
        p += sizeof(::fuse_in_header);

        if (sub_h.len < sizeof(::fuse_in_header) ||
            static_cast<std::size_t>(end - p) <
                sub_h.len - sizeof(::fuse_in_header)) {
            reply_error(r, Errc::invalid_argument); return;
        }
        const std::size_t sub_len = sub_h.len - sizeof(::fuse_in_header);

        if (sub_req.dep_index != FUSE_COMPOUND_NO_DEP &&
            sub_req.dep_index < produced.size())
            sub_h.nodeid = produced[sub_req.dep_index];

        if (log) {
            if (!produced.empty()) std::fputc(',', stderr);
            std::fputs(opcode_name(sub_h.opcode), stderr);
            if (sub_req.dep_index != FUSE_COMPOUND_NO_DEP)
                std::fprintf(stderr, "^%u", sub_req.dep_index);
        }

        Replier sub_r{ .out    = out_p + sizeof(::fuse_out_header),
                       .cap    = static_cast<std::size_t>(out_end - out_p) -
                                 sizeof(::fuse_out_header),
                       .unique = sub_h.unique };
        if (sub_h.opcode == FUSE_COMPOUND)
            reply_error(sub_r, Errc::operation_not_supported);
        else
            dispatch(sub_h, p, sub_len, sub_r);
        p += sub_len;

        // Entry-producing opcodes return fuse_entry{x,}_out, both of
        // which have the nodeid as their first u64. Anything else
        // contributes 0 to the produced[] slot.
        std::uint64_t prod = 0;
        if (!sub_r.neg_err && sub_r.len >= sizeof(prod)) {
            switch (sub_h.opcode) {
            case FUSE_LOOKUPX:
            case FUSE_MKOBJX:
            case FUSE_LOOKUP_ROOT:
                std::memcpy(&prod, sub_r.out, sizeof(prod));
                break;
            }
        }
        produced.push_back(prod);

        ::fuse_out_header oh{ .len    = static_cast<std::uint32_t>(
                                  sizeof(::fuse_out_header) +
                                  (sub_r.neg_err ? 0u : sub_r.len)),
                              .error  = sub_r.neg_err,
                              .unique = sub_h.unique };
        std::memcpy(out_p, &oh, sizeof(oh));
        out_p += oh.len;
    }

    if (log) std::fputs("]\n", stderr);

    r.neg_err = 0;
    r.len     = static_cast<std::size_t>(out_p - r.out);
}

// -----------------------------------------------------------------------
// Top-level dispatch
// -----------------------------------------------------------------------

void Session::Impl::dispatch(const ::fuse_in_header& h,
                             const std::byte* body, std::size_t body_len,
                             Replier& r) noexcept
{
    switch (h.opcode) {
    case FUSE_INIT:        handle_init       (h, body, body_len, r); break;
    case FUSE_LOOKUP_ROOT: handle_lookup_root(h, body, body_len, r); break;
    case FUSE_LOOKUPX:     handle_lookupx    (h, body, body_len, r); break;
    // FORGET has no kernel-side reply, but we still call reply_ok() so
    // the io_uring worker submits a zero-length COMMIT_AND_FETCH that
    // re-arms this entry's ring slot. The kernel discards the reply
    // payload for these opcodes.
    case FUSE_FORGET:       handle_forget       (h, body, body_len, r); break;
    case FUSE_BATCH_FORGET: handle_batch_forget (h, body, body_len, r); break;
    case FUSE_STATX:       handle_statx      (h, body, body_len, r); break;
    case FUSE_SETSTATX:    handle_setstatx   (h, body, body_len, r); break;
    case FUSE_MKOBJX:      handle_mkobjx     (h, body, body_len, r); break;
    case FUSE_UNLINK:      handle_unlink     (h, body, body_len, r, false); break;
    case FUSE_RMDIR:       handle_unlink     (h, body, body_len, r, true);  break;
    case FUSE_RENAME2:     handle_rename2    (h, body, body_len, r); break;
    case FUSE_LINK:        handle_link       (h, body, body_len, r); break;
    case FUSE_READ:        handle_read       (h, body, body_len, r); break;
    case FUSE_WRITE:       handle_write      (h, body, body_len, r); break;
    case FUSE_READLINK:    handle_readlink   (h, body, body_len, r); break;
    case FUSE_STATFS:      handle_statfs     (h, body, body_len, r); break;
    case FUSE_FALLOCATE:   handle_fallocate  (h, body, body_len, r); break;
    case FUSE_OPEN:        handle_open       (h, body, body_len, r); break;
    case FUSE_RELEASE:     handle_release    (h, body, body_len, r); break;
    case FUSE_OPENDIR:     handle_opendir    (h, body, body_len, r); break;
    case FUSE_RELEASEDIR:  handle_releasedir (h, body, body_len, r); break;
    case FUSE_READDIR:     handle_readdir    (h, body, body_len, r); break;
    case FUSE_GETXATTR:    handle_getxattr   (h, body, body_len, r); break;
    case FUSE_SETXATTR:    handle_setxattr   (h, body, body_len, r); break;
    case FUSE_LISTXATTR:   handle_listxattr  (h, body, body_len, r); break;
    case FUSE_REMOVEXATTR: handle_removexattr(h, body, body_len, r); break;
    case FUSE_COMPOUND:    handle_compound   (h, body, body_len, r); break;
    default:
        reply_error(r, Errc::function_not_supported);
        break;
    }
}

}  // namespace fex
