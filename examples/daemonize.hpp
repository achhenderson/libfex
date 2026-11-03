// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
//
// daemonize.hpp - what the example daemons do around Session::run(): signal
// handling, and going into the background once the mount is live.

#pragma once

#include <fex/fex.hpp>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

// =======================================================================
//                            Daemonize plumbing
// =======================================================================
//
// Standard FUSE-style mount-helper daemonization: fork, parent waits on
// a pipe until the child reports the mount is live, then exits. This
// lets the daemon be invoked from /etc/fstab or `mount -t fusex` and
// have the caller's `mount` syscall semantics preserved -- the parent
// only returns success once the kernel has actually moved the new
// superblock into the namespace.
//
// Readiness detection: `fex::Session::run()` mounts and then blocks
// until unmount, so we can't poll a return value. Instead, we record
// the mountpoint's st_dev before fork; once it changes, the mount is
// installed. A small watchdog thread polls in the child and writes a
// byte to the pipe when it sees the new st_dev. If `run()` fails before
// the mount is ever installed, the pipe is closed without a byte and
// the parent exits non-zero.

namespace fex_example {

// Owning fd pair for the parent/child handshake pipe. RAII so we don't
// leak descriptors on any error path.
struct PipePair {
    int r = -1;
    int w = -1;
    ~PipePair() {
        if (r >= 0) ::close(r);
        if (w >= 0) ::close(w);
    }
};

// Shared state between the daemon's main thread and the readiness
// watchdog. `done` flips when run() returns; the watchdog observes it
// on the next poll tick and stops checking, avoiding a 30s hang if the
// mount fails to come up at all.
struct DaemonReady {
    std::atomic<bool> done{false};
    int pipe_w = -1;  // owned by watchdog after launch
};

// Poll the mountpoint until its st_dev changes (mount visible) or
// `ready->done` flips (run() returned, presumably with an error). We
// signal success with a single byte; failure is communicated as EOF
// when the pipe is closed.
inline void readiness_watchdog(std::shared_ptr<DaemonReady> ready,
                        std::string mountpoint,
                        dev_t before_dev) {
    using namespace std::chrono_literals;
    constexpr int kMaxIters = 600;  // ~30s at 50ms ticks
    for (int i = 0; i < kMaxIters; ++i) {
        if (ready->done.load(std::memory_order_acquire))
            break;
        struct ::stat st;
        if (::stat(mountpoint.c_str(), &st) == 0 && st.st_dev != before_dev) {
            char b = 1;
            (void)!::write(ready->pipe_w, &b, 1);
            break;
        }
        std::this_thread::sleep_for(50ms);
    }
    int w = ready->pipe_w;
    ready->pipe_w = -1;
    if (w >= 0) ::close(w);
}

// Signal handling: we want SIGINT/SIGTERM to trigger an orderly
// session shutdown so the mount unwinds cleanly. The signal handler
// can't call session.stop() directly across translation units without
// a static hook, so park a pointer here.
inline fex::Session* g_session = nullptr;

inline void on_term_signal(int) noexcept {
    if (g_session) g_session->stop();
}

inline void install_signal_handlers(fex::Session& s) {
    g_session = &s;
    struct sigaction sa{};
    sa.sa_handler = on_term_signal;
    ::sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGINT,  &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGHUP,  &sa, nullptr);
    // SIGPIPE: ignore so a broken handshake pipe doesn't kill us.
    struct sigaction si{};
    si.sa_handler = SIG_IGN;
    ::sigemptyset(&si.sa_mask);
    ::sigaction(SIGPIPE, &si, nullptr);
}

// Run the session in the foreground, or fork and run it in the child with the
// parent returning once the mount is live. Returns the exit code for main().
inline int run_session(fex::Session& session, fex::Filesystem& fs, const char* mountpoint,
                       bool foreground, const char* progname)
{
    if (foreground) {
        if (auto ec = session.run(fs); ec) {
            std::fprintf(stderr, "fex session: %s\n", ec.message().c_str());
            return 1;
        }
        return 0;
    }

    // ---- Daemonize ---------------------------------------------------
    //
    // Record the pre-mount st_dev so the child's watchdog can detect
    // when the new superblock appears at the mountpoint.
    struct ::stat before_st;
    if (::stat(mountpoint, &before_st) < 0) {
        std::perror("stat mountpoint");
        return 1;
    }

    PipePair pp;
    {
        int fds[2];
        if (::pipe2(fds, O_CLOEXEC) < 0) {
            std::perror("pipe2");
            return 1;
        }
        pp.r = fds[0];
        pp.w = fds[1];
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        std::perror("fork");
        return 1;
    }

    if (pid > 0) {
        // Parent: drop write end, then block on the read end. A single
        // byte means the child saw the mount go live; EOF means the
        // child closed the pipe without ever signalling readiness.
        ::close(pp.w);
        pp.w = -1;
        char b = 0;
        ssize_t n;
        do { n = ::read(pp.r, &b, 1); } while (n < 0 && errno == EINTR);
        if (n == 1) return 0;
        std::fprintf(stderr, "%s: child exited before mount came up\n", progname);
        // Best-effort reap so the child doesn't linger as a zombie if
        // it died fast.
        int status = 0;
        (void)::waitpid(pid, &status, WNOHANG);
        return 1;
    }

    // Child: drop the read end and detach from the controlling tty.
    ::close(pp.r);
    pp.r = -1;
    if (::setsid() < 0) {
        // Non-fatal; we just won't get our own session.
    }

    // Redirect stdio to /dev/null so the daemon doesn't hold the
    // terminal's fds. The init() heartbeat is fire-and-forget at this
    // point; users wanting trace output should run with -f.
    if (int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC); devnull >= 0) {
        ::dup2(devnull, STDIN_FILENO);
        ::dup2(devnull, STDOUT_FILENO);
        ::dup2(devnull, STDERR_FILENO);
        if (devnull > 2) ::close(devnull);
    }

    auto ready = std::make_shared<DaemonReady>();
    ready->pipe_w = pp.w;
    pp.w = -1;  // ownership moved into watchdog

    std::thread watchdog(readiness_watchdog, ready,
                         std::string(mountpoint), before_st.st_dev);

    auto ec = session.run(fs);
    ready->done.store(true, std::memory_order_release);
    if (watchdog.joinable()) watchdog.join();

    return ec ? 1 : 0;
}

}  // namespace fex_example
