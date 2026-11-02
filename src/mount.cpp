// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// Mount setup: fsopen + fsconfig(SET_FD) (phase 1) and
// fsconfig(CMD_CREATE) + fsmount + move_mount (phase 2).
//
// Phase 1 runs on the main thread before any ring REGISTERs are
// submitted; the kernel-side fusex parser installs the channel into
// the fud during SET_FD so subsequent FUSE_IO_URING_CMD_REGISTERs find
// fud->chan. Phase 2 runs on a helper thread because CMD_CREATE blocks
// inside fill_super while it sends INIT/LOOKUP_ROOT/STATX through the
// rings the workers have already armed.

#include "session_impl.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>
#include <utility>

#include <fcntl.h>            // AT_FDCWD
#include <linux/mount.h>      // FSCONFIG_*, MOVE_MOUNT_*, FSMOUNT_*
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x4000U
#endif

// -----------------------------------------------------------------------
// Syscall wrappers. glibc 2.36+ exposes fsopen/fsconfig/fsmount/move_mount
// but we prefer the syscall path so the library builds on older glibcs.
// -----------------------------------------------------------------------

#ifndef __NR_fsopen
#  define __NR_fsopen     430
#endif
#ifndef __NR_fsconfig
#  define __NR_fsconfig   431
#endif
#ifndef __NR_fsmount
#  define __NR_fsmount    432
#endif
#ifndef __NR_move_mount
#  define __NR_move_mount 429
#endif

namespace {

int sys_fsopen(const char* fsname, unsigned int flags) {
    return static_cast<int>(::syscall(__NR_fsopen, fsname, flags));
}
int sys_fsconfig(int fsfd, unsigned int cmd, const char* key,
                 const void* value, int aux) {
    return static_cast<int>(::syscall(__NR_fsconfig, fsfd, cmd, key, value, aux));
}
int sys_fsmount(int fsfd, unsigned int flags, unsigned int attr_flags) {
    return static_cast<int>(::syscall(__NR_fsmount, fsfd, flags, attr_flags));
}
int sys_move_mount(int from_dfd, const char* from_path,
                   int to_dfd, const char* to_path, unsigned int flags) {
    return static_cast<int>(::syscall(__NR_move_mount, from_dfd, from_path,
                                      to_dfd, to_path, flags));
}

}  // anonymous

namespace fex {

// Phase 1: fsopen + fsconfig(SET_FD). Runs on the main thread before any
// io_uring REGISTER cmds are submitted. The kernel-side patch installs the
// channel into the fud during SET_FD so the daemon's subsequent REGISTERs
// find fud->chan.
std::expected<UniqueFd, std::error_code>
Session::Impl::mount_open_and_set_fd()
{
    const int fsfd = sys_fsopen("fusex", 0);
    if (fsfd < 0) {
        std::fprintf(stderr, "fex mount: fsopen(\"fusex\") -> errno=%d (%s)\n",
                     errno, ::strerror(errno));
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    UniqueFd fsfd_holder(fsfd);

    // FSCONFIG_SET_FD passes a file descriptor through the fs_context
    // (aux carries the fd; value is NULL). The fusex kernel parser
    // requires this exact form for "fd=".
    if (sys_fsconfig(fsfd, /*FSCONFIG_SET_FD*/ 5, "fd", nullptr,
                     dev_fd.get()) < 0) {
        std::fprintf(stderr, "fex mount: fsconfig(SET_FD, fd=%d) -> errno=%d (%s)\n",
                     dev_fd.get(), errno, ::strerror(errno));
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // "source" is a VFS-generic key handled by vfs_parse_fs_string before
    // the filesystem's parse_param sees it; it lands in fc->source and
    // becomes the first column of /proc/self/mountinfo. Without it the
    // kernel records "none".
    if (!opts.source.empty()) {
        if (sys_fsconfig(fsfd, /*FSCONFIG_SET_STRING*/ 1, "source",
                         opts.source.c_str(), 0) < 0) {
            std::fprintf(stderr,
                "fex mount: fsconfig(SET_STRING, source=%s) -> errno=%d (%s)\n",
                opts.source.c_str(), errno, ::strerror(errno));
            return std::unexpected(std::error_code(errno, std::system_category()));
        }
    }
    return fsfd_holder;
}

// Phase 2: fsconfig(CMD_CREATE) + fsmount + move_mount. Runs on the mount
// thread. CMD_CREATE blocks while the kernel sends INIT/LOOKUP_ROOT/STATX
// through the rings the worker threads registered in between phases.
std::error_code Session::Impl::mount_create_and_finish(UniqueFd fsfd)
{
    // FSCONFIG_CMD_CREATE triggers fusex_fill_super which performs
    // INIT/LOOKUP_ROOT/STATX synchronously. The kernel routes these
    // via fuse_io_uring_ops because the daemon registered the rings
    // before this call.
    if (sys_fsconfig(fsfd.get(), /*FSCONFIG_CMD_CREATE*/ 6, nullptr,
                     nullptr, 0) < 0) {
        std::fprintf(stderr, "fex mount: fsconfig(CMD_CREATE) -> errno=%d (%s)\n",
                     errno, ::strerror(errno));
        return {errno, std::system_category()};
    }

    unsigned int attr_flags = 0;
    if (opts.read_only) attr_flags |= /*MOUNT_ATTR_RDONLY*/ 0x1;

    const int mntfd = sys_fsmount(fsfd.get(), /*FSMOUNT_CLOEXEC*/ 0x1, attr_flags);
    if (mntfd < 0) {
        std::fprintf(stderr, "fex mount: fsmount -> errno=%d (%s)\n",
                     errno, ::strerror(errno));
        return {errno, std::system_category()};
    }
    UniqueFd mnt(mntfd);

    if (sys_move_mount(mntfd, "", AT_FDCWD, opts.mountpoint.c_str(),
                       /*MOVE_MOUNT_F_EMPTY_PATH*/ 0x4) < 0) {
        std::fprintf(stderr, "fex mount: move_mount(-> %s) -> errno=%d (%s)\n",
                     opts.mountpoint.c_str(), errno, ::strerror(errno));
        return {errno, std::system_category()};
    }

    // Mount now lives in the namespace; Session::run() must umount on
    // teardown so a crashed/exited daemon doesn't leave stale entries
    // in /proc/self/mountinfo for the next run. Only this mount though,
    // it may be gone by then.
    struct ::statx stx;
    if (::statx(mntfd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC,
                STATX_MNT_ID_UNIQUE, &stx) == 0 &&
        (stx.stx_mask & STATX_MNT_ID_UNIQUE)) {
        mount_id = stx.stx_mnt_id;
        mount_installed = true;
    }

    // Once moved into place, the mount fd may be closed; the actual
    // mount persists in the namespace.
    return {};
}

}  // namespace fex
