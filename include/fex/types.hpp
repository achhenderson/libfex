// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// fex/types.hpp - public C++ value types used throughout libfex.
//
// These wrap the wire structs from <fex/abi.h> with strong-typed,
// default-zeroed C++ versions. The internal dispatcher converts wire
// payloads to these and back; user code never includes the ABI header.

#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace fex {

// ---- strong typedefs ----------------------------------------------------

// nodeid as understood by the kernel. The root inode is always nodeid()==1.
enum class NodeId : std::uint64_t { invalid = 0, root = 1 };

constexpr std::uint64_t to_underlying(NodeId n) noexcept {
    return static_cast<std::uint64_t>(n);
}

// Opaque file handle the daemon hands back from opendir. The fusex kernel
// module does not call FUSE_OPEN for regular files, so this is dirhandle-only.
enum class FileHandle : std::uint64_t {};

constexpr std::uint64_t to_underlying(FileHandle h) noexcept {
    return static_cast<std::uint64_t>(h);
}

// ---- statx (host-friendly mirror of struct fuse_statx) ------------------

// statx mask bits, mirroring the Linux statx UAPI exactly so that values
// observed in StatxIn::mask are directly usable.
namespace statx_mask {
inline constexpr std::uint32_t type   = 0x1u;
inline constexpr std::uint32_t mode   = 0x2u;
inline constexpr std::uint32_t nlink  = 0x4u;
inline constexpr std::uint32_t uid    = 0x8u;
inline constexpr std::uint32_t gid    = 0x10u;
inline constexpr std::uint32_t atime  = 0x20u;
inline constexpr std::uint32_t mtime  = 0x40u;
inline constexpr std::uint32_t ctime  = 0x80u;
inline constexpr std::uint32_t ino    = 0x100u;
inline constexpr std::uint32_t size   = 0x200u;
inline constexpr std::uint32_t blocks = 0x400u;
inline constexpr std::uint32_t basic  = 0x7ffu;
inline constexpr std::uint32_t btime  = 0x800u;
}  // namespace statx_mask

struct Timespec {
    std::int64_t  sec  = 0;
    std::uint32_t nsec = 0;

    constexpr bool valid() const noexcept {
        return nsec < 1'000'000'000u;
    }
};

// All fields default to zero. `mask` selects which fields are meaningful;
// callers must set both `mask` and the matching field on responses, and
// must inspect `mask` on requests (SETSTATX).
struct StatxOut {
    std::uint32_t mask           = 0;
    std::uint32_t blksize        = 0;
    std::uint64_t attributes     = 0;
    std::uint32_t nlink          = 0;
    std::uint32_t uid            = 0;
    std::uint32_t gid            = 0;
    std::uint16_t mode           = 0;
    std::uint64_t ino            = 0;
    std::uint64_t size           = 0;
    std::uint64_t blocks         = 0;
    std::uint64_t attributes_mask = 0;
    Timespec      atime;
    Timespec      btime;
    Timespec      ctime;
    Timespec      mtime;
    std::uint32_t rdev_major     = 0;
    std::uint32_t rdev_minor     = 0;
    std::uint32_t dev_major      = 0;
    std::uint32_t dev_minor      = 0;
};

// Subset of StatxOut to apply: the kernel sets `mask` to indicate which
// fields the daemon must mutate, leaves the rest zero.
struct SetStatxIn {
    std::uint32_t mask = 0;
    std::uint16_t mode = 0;
    std::uint32_t uid  = 0;
    std::uint32_t gid  = 0;
    std::uint64_t size = 0;
    Timespec      atime;
    Timespec      ctime;
    Timespec      mtime;
};

// kstatfs mirror.
struct StatfsOut {
    std::uint64_t blocks  = 0;
    std::uint64_t bfree   = 0;
    std::uint64_t bavail  = 0;
    std::uint64_t files   = 0;
    std::uint64_t ffree   = 0;
    std::uint32_t bsize   = 0;
    std::uint32_t namelen = 0;
    std::uint32_t frsize  = 0;
};

// ---- per-opcode payloads ------------------------------------------------

// Returned by lookupx() / lookup_root(): identifies an inode and how long
// the kernel may cache the (parent,name) -> nodeid binding.
struct EntryOut {
    NodeId       nodeid       = NodeId::invalid;
    std::chrono::nanoseconds entry_valid{0};
    bool         negative     = false;  // negative-dentry caching
};

// Caller-context (uid/gid/pid) extracted from the request header. Used by
// permission checks and ownership-from-context creation.
struct Context {
    std::uint32_t uid   = 0;
    std::uint32_t gid   = 0;
    std::uint32_t pid   = 0;
    NodeId        nodeid = NodeId::invalid;
    std::uint64_t unique = 0;
};

// Result of MKOBJX: the daemon must allocate a nodeid, persist the
// object, and report back the *initial* StatxOut so the kernel can finish
// inode setup. The kernel will follow up with a separate STATX before
// using the inode, but the initial reply is what binds parent dentry to
// the new nodeid.
struct MkobjxIn {
    StatxOut      stat;
    std::uint32_t flags = 0;     // FUSE_MKOBJX_TMPFILE etc.
    std::string_view name;       // child name in parent dir (no trailing NUL)
    std::string_view link_target;// non-empty only for S_IFLNK
};

constexpr std::uint32_t kMkobjxTmpfile = 1U << 0;

struct OpenOut {
    FileHandle    fh          = FileHandle{0};
    std::uint32_t open_flags  = 0;
};

// INIT negotiation. Daemons receive the kernel's announce and write back
// the flags they support. Returned by Filesystem::init().
struct InitInfo {
    // From the kernel:
    std::uint32_t kernel_major = 0;
    std::uint32_t kernel_minor = 0;
    std::uint64_t kernel_flags = 0;   // flags | (flags2 << 32)
    std::uint32_t max_readahead = 0;

    // To the kernel (default-filled with sensible values):
    std::uint64_t flags = 0;          // see fex/abi.h FUSE_* and the
                                      // flags2 bits OR'd up into bits 32+
    std::uint32_t max_write = 1u << 20;   // 1 MiB
    std::uint16_t max_pages = 256;
    std::uint32_t time_gran = 1;
};

// ---- error code helpers -------------------------------------------------

// We use std::errc for filesystem errors. Daemons return them via
// std::expected<T, std::errc>. The dispatcher translates these to
// negative errno on the wire.
using Errc = std::errc;

// Convenience: turn an errno value into std::errc. Returns
// std::errc::io_error for unknown values rather than truncating.
inline Errc errc_from_errno(int err) noexcept {
    return static_cast<Errc>(err);
}

}  // namespace fex
