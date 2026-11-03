# libfex

A modern C++23 library for writing **fusex** filesystem daemons.

`fusex` is a kernel-side variant of FUSE introduced by the patches at
`fs/fuse/fusex.c` in the linked kernel tree. It speaks a leaner dialect
of the FUSE wire protocol — four new opcodes
(`LOOKUP_ROOT`, `LOOKUPX`, `MKOBJX`, `SETSTATX`), `FUSE_STATX`, no
`FUSE_OPEN` for regular files, mandatory synchronous INIT, mounted via
`fsopen`/`fsconfig`/`fsmount` only — and rejects regular libfuse
daemons. This library is the userspace counterpart.

It is *not* a thin wrapper around libfuse 3. There is no `struct
fuse_operations` of function pointers, no `void *user_data`, no signal
handling magic, and no command-line option parser. You inherit one
class:

```cpp
class fex::Filesystem {
    virtual std::expected<EntryOut,  Errc> lookup_root(const Context&)              = 0;
    virtual std::expected<EntryOut,  Errc> lookupx(const Context&, NodeId, std::string_view) = 0;
    virtual std::expected<StatxOut,  Errc> statx(const Context&, NodeId)            = 0;
    // ... default-implemented (-ENOSYS) callbacks for everything else
};
```

…and pass an instance to `fex::Session::run()`. Errors are
`std::expected<T, std::errc>`. Buffers are `std::span<std::byte>`. RAII
owns every fd.

## Status

Functional, multi-threaded over FUSE-over-io_uring. Implements the
full opcode set the kernel module currently emits:
lookup/statx/setstatx/mkobjx, unlink/rmdir/rename2/link,
read/write/readlink, opendir/releasedir/readdir, statfs, fallocate,
fsync/fsyncdir/syncfs, getxattr/setxattr/listxattr/removexattr, plus INIT
negotiation.
Includes a worked passthrough example.

Threading: the session spawns `SessionOptions::uring_threads` worker
threads (default = `hardware_concurrency()`, clamped to [1,32]), each
owning one io_uring. The kernel has one FUSE queue per possible CPU and
doesn't serve anything before each has an entry, so all the queues are
registered, `uring_queue_depth` entries each, and divided among the
threads. Filesystem callbacks may run concurrently — implementations
must be thread-safe.

Everything is io_uring only, in both directions. The daemon registers
its ring entries between `fsconfig(SET_FD)` and `fsconfig(CMD_CREATE)`
and the mount-time handshake (INIT/LOOKUP_ROOT/STATX) already comes over
them. `read()`/`write()` on `/dev/fuse` fail for a fusex connection.

Notifications (`Session::notify_*()`) go over `FUSE_IO_URING_CMD_NOTIFY`
on a ring of their own. See `<fex/session.hpp>`.

Note that at the moment of this writing fusex is not upstream and needs
the patches on top of it to work this way.

## Requirements

* gcc 13+ or clang 17+ (`std::expected`, designated init, C++23)
* Linux kernel with `fusex` filesystem registered
  (`grep fusex /proc/filesystems` should show it) and
  FUSE-over-io_uring support (Linux 6.10+)
* liburing 2.5+ (`pkg-config --modversion liburing`)
* `/dev/fuse` accessible

## Build

Either:

```sh
make -j$(nproc)            # → build/libfex.{a,so,so.0,so.0.1.0}, build/fex-passthrough, build/fex-memfs
sudo make install          # → /usr/local
```

Or with CMake (>= 3.20):

```sh
cmake -S . -B build -G Ninja
cmake --build build
sudo cmake --install build
```

## Use

```cpp
#include <fex/fex.hpp>

class MyFs : public fex::Filesystem {
    std::expected<fex::EntryOut, fex::Errc>
    lookup_root(const fex::Context&) override {
        return fex::EntryOut{
            .nodeid = fex::NodeId::root,
            .entry_valid = std::chrono::seconds(1),
        };
    }
    std::expected<fex::EntryOut, fex::Errc>
    lookupx(const fex::Context&, fex::NodeId parent,
            std::string_view name) override { /* ... */ }
    std::expected<fex::StatxOut, fex::Errc>
    statx(const fex::Context&, fex::NodeId) override { /* ... */ }
};

int main() {
    MyFs fs;
    fex::Session s({.mountpoint = "/mnt/myfs"});
    return s.run(fs).value();
}
```

Compile with `-std=c++23 -lfex -lpthread -luring`.

## Passthrough example

```sh
mkdir -p /tmp/backing /tmp/mnt
echo hello > /tmp/backing/greeting

# In one terminal:
build/fex-passthrough /tmp/backing /tmp/mnt

# In another:
ls -la /tmp/mnt
cat /tmp/mnt/greeting
```

The example daemon mirrors `<backing_dir>` byte-for-byte: every fusex
callback runs the equivalent `*at()` syscall against an `O_PATH` fd of
the backing directory. Inode numbers from the backing fs are reused as
fusex nodeids.

To unmount:

```sh
sudo umount /tmp/mnt
```

…or stop the daemon: on SIGINT or SIGTERM it writes back what is dirty
and unmounts.

## In-memory example

```sh
mkdir -p /tmp/mnt
build/fex-memfs /tmp/mnt       # -f to stay in the foreground
```

`fex-memfs` is the counterpart of libfuse's `memfs_ll`: everything lives in
the daemon and is gone when it ends. The data of a regular file is in a memfd,
so it is sparse and swappable, and takes one file descriptor per file. It does
what the kernel asks of a daemon: directories, hard links and symlinks, special
files, `O_TMPFILE`, all the `RENAME_*` flags, xattrs and so ACLs, `fallocate`,
and the timestamps. `df` shows the machine's memory.

Options, with `-o`:

| Option | Meaning |
|---|---|
| `max_write=N` | largest request in bytes, default from `/proc/sys/fs/fuse/max_pages_limit` |
| `threads=N`, `queue_depth=N` | ring worker threads, entries per queue |
| `null_io` | no data store, to measure the interface: writes read the buffer, reads return random data, files remember only their size |
| `debug_io` | log every read and write to stderr with a timestamp |
| `notify_inval` | a thread fires storms of invalidations at random files the kernel knows, as peer nodes would |
| `notify_interval_ms=N` | longest delay between storms, default 1000 |
| `notify_storm=N` | invalidations per storm, default 64 |

The `memfs_ll` options for the page cache and passthrough don't apply: fusex
has neither on the data path.

## Testing

`build/fex-notify-test <empty_dir>` needs root and a kernel with fusex. It
mounts an in-memory filesystem and checks what a daemon can rely on: direct
reads and writes, mappings and their coherence with those, exec from the
mount, fsync/syncfs and the daemon's timestamps. Then every notification: it
changes the server's state, checks that the kernel doesn't know yet, sends
the notification and checks that the kernel shows the change. It reports each
check and exits non-zero if one fails.

## Design notes — why not libfuse?

The fusex kernel module diverges from upstream FUSE in several ways
that make a fresh library cheaper than reshaping libfuse:

* **No `FUSE_OPEN`.** The kernel issues `FUSE_READ`/`FUSE_WRITE`
  directly against a nodeid, no per-open file handle. libfuse's
  `fi->fh` plumbing has nothing to track.
* **`FUSE_LOOKUP_ROOT` happens during mount.** The daemon must answer
  it (and the immediate follow-up `FUSE_STATX`) inside
  `fsconfig(CMD_CREATE)`. Our `Session::run()` runs the mount on a
  helper thread while the ring workers serve these.
* **`FUSE_MKOBJX`** collapses CREATE/MKDIR/MKNOD/SYMLINK/TMPFILE into
  one opcode keyed on `mode & S_IFMT`. We expose it as a single
  `mkobjx()` callback rather than five.
* **`FUSE_LINK` reply must be empty** — see `fusex-review.md` item 5b.
  Our `link()` returns `std::expected<void, Errc>`, not an `EntryOut`.
* **Server-driven invalidation.** The kernel ignores `entry_valid` /
  `attr_valid` timeouts; daemons must emit `FUSE_NOTIFY_INVAL_*` to
  invalidate, see `Session::notify_*()`.
* **The daemon does the caching.** Every `read(2)` and `write(2)` arrives as
  `FUSE_READ`/`FUSE_WRITE`, directories and symlinks aren't cached either.
  Only mappings use the page cache: dirty pages come back as ordinary
  `FUSE_WRITE`s, on `fsync`, `sync` and unmount at the latest. Durability is
  `fsync()`/`fsyncdir()`/`syncfs()`; without them those calls just succeed.
  `FUSE_NOTIFY_STORE` and `FUSE_NOTIFY_RETRIEVE` don't exist here.
* **The daemon owns the timestamps.** The kernel stamps nothing and fetches
  them with `statx()`: see the conventions in `<fex/filesystem.hpp>`.
* **Sync-INIT is mandatory.** `FUSE_DEV_IOC_SYNC_INIT` must be issued
  on the `/dev/fuse` fd before passing it to `fsconfig`.
  `fex::open_fex_device()` does this for you.

## Licensing

`include/fex/abi.h` is BSD-2-Clause OR GPL-2.0 (kernel UAPI). The
rest is BSD-2-Clause OR GPL-2.0 at the user's choice — same dual
license libfuse uses.
