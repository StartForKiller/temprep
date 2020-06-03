#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/sysdeps.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <wivos/fcntl.h>
#include <limits.h>

#define STUB_ONLY { __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }

namespace mlibc {

    // Unknown Functions
    //int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) STUB_ONLY
    
    void sys_libc_log(const char *message) {
        unsigned long res;
        asm volatile ("syscall" : "=a"(res)
                : "a"(0), "S"(message)
                : "rcx", "r11", "rdx");
    }

    void sys_libc_panic() {
        mlibc::infoLogger() << "\e[31mmlibc: panic!" << frg::endlog;
        while(1);
    }

    // Memory Related Functions
    int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
        __ensure(flags & MAP_ANONYMOUS);
        void *res;
        size_t size_in_pages = (size + 4096 - 1) / 4096;
        asm volatile ("syscall" : "=a"(res)
                : "a"(6), "D"(hint), "S"(size_in_pages)
                : "rcx", "r11");
        if(!res)
            return -1;
        *window = res;
        return 0;
    }
    /*#ifndef MLIBC_BUILDING_RTDL
    int sys_vm_remap(void *pointer, size_t size, size_t new_size, void **window) STUB_ONLY
    #endif*/
    int sys_vm_unmap(void *pointer, size_t size) STUB_ONLY

    // Misc functions
    #ifndef MLIBC_BUILDING_RTDL
    int sys_clock_get(int clock, time_t *secs, long *nanos) STUB_ONLY

    int sys_futex_wait(int *pointer, int expected) STUB_ONLY
    int sys_futex_wake(int *pointer) STUB_ONLY

    // Task functions
    void sys_exit(int status){
        while(1); // TODO
    }

    int sys_tcb_set(void *pointer){
        int res;
        asm volatile ("syscall" : "=a"(res)
                : "a"(5), "D"(pointer)
                : "rcx", "r11", "rdx");
        return res;
    }
    #endif



    /*#ifndef MLIBC_BUILDING_RTDL
    int sys_sleep(time_t *secs, long *nanos) STUB_ONLY
    int sys_fork(pid_t *child) STUB_ONLY
    int sys_execve(const char *path, char *const argv[], char *const envp[]) STUB_ONLY
    int sys_kill(pid_t pid, int signal) STUB_ONLY
    int sys_waitpid(pid_t pid, int *status, int flags, pid_t *ret_pid) STUB_ONLY
    int sys_getrusage(int who, struct rusage *usage) STUB_ONLY
    int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) STUB_ONLY
    void sys_yield() STUB_ONLY
    gid_t sys_getgid() STUB_ONLY
    gid_t sys_getegid() STUB_ONLY
    uid_t sys_getuid() STUB_ONLY
    uid_t sys_geteuid() STUB_ONLY
    pid_t sys_getpid() STUB_ONLY
    pid_t sys_getppid() STUB_ONLY
    #endif*/

    // File functions
    int sys_open(const char *path, int flags, int *fd) {
        int ret;
        int sys_errno;

        asm volatile ("syscall"
                : "=a"(ret), "=d"(sys_errno)
                : "a"(3), "D"(path), "S"(flags), "d"(0)
                : "rcx", "r11");

        if (ret == -1)
            return sys_errno;

        *fd = ret;
        return 0;
    }
    int sys_close(int fd){
        int ret;
        int sys_errno;

        asm volatile ("syscall"
                : "=a"(ret), "=d"(sys_errno)
                : "a"(4), "D"(fd)
                : "rcx", "r11");

        if (ret == -1)
            return sys_errno;

        return 0;
    }
    int sys_seek(int fd, off_t offset, int whence, off_t *new_offset){
        return ESPIPE;
    }
    int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
        ssize_t ret;
        int sys_errno;

        asm volatile ("syscall"
                : "=a"(ret), "=d"(sys_errno)
                : "a"(1), "D"(fd), "S"(buf), "d"(count)
                : "rcx", "r11");

        if (ret == -1)
            return sys_errno;

        *bytes_read = ret;
        return 0;
    }

    #ifndef MLIBC_BUILDING_RTDL
    int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
        ssize_t ret;
        int sys_errno;

        asm volatile ("syscall"
                : "=a"(ret), "=d"(sys_errno)
                : "a"(2), "D"(fd), "S"(buf), "d"(count)
                : "rcx", "r11");

        if (ret == -1)
            return sys_errno;

        *bytes_written = ret;
        return 0;
    }
    #endif

    /*
    int sys_ioctl(int fd, unsigned long request, void *arg, int *result) STUB_ONLY
    int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) STUB_ONLY
    int sys_rename(const char *path, const char *new_path) STUB_ONLY
    int sys_open_dir(const char *path, int *handle) STUB_ONLY
    int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) STUB_ONLY
    int sys_access(const char *path, int mode) STUB_ONLY
    int sys_dup(int fd, int flags, int *newfd) STUB_ONLY
    int sys_dup2(int fd, int flags, int newfd) STUB_ONLY
    int sys_isatty(int fd) STUB_ONLY
    int sys_ttyname(int fd, char *buf, size_t size) STUB_ONLY
    int sys_chroot(const char *path) STUB_ONLY
    int sys_mkdir(const char *path) STUB_ONLY
    int sys_tcgetattr(int fd, struct termios *attr) STUB_ONLY
    int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) STUB_ONLY
    int sys_tcflow(int fd, int action) STUB_ONLY
    int sys_pipe(int *fds, int flags) STUB_ONLY
    int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length) STUB_ONLY
    int sys_ftruncate(int fd, size_t size) STUB_ONLY
    int sys_fallocate(int fd, off_t offset, size_t size) STUB_ONLY
    int sys_unlink(const char *path) STUB_ONLY
    int sys_symlink(const char *target_path, const char *link_path) STUB_ONLY
    int sys_fcntl(int fd, int request, va_list args, int *result) STUB_ONLY
    #endif
    // Network related functions
    #ifndef MLIBC_BUILDING_RTDL
    int sys_socket(int family, int type, int protocol, int *fd) STUB_ONLY
    int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) STUB_ONLY
    int sys_accept(int fd, int *newfd) STUB_ONLY
    int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) STUB_ONLY
    int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) STUB_ONLY
    int sys_msg_send(int fd, const struct msghdr *hdr, int flags, ssize_t *length) STUB_ONLY
    int sys_msg_recv(int fd, struct msghdr *hdr, int flags, ssize_t *length) STUB_ONLY
    int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) STUB_ONLY
    int sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) STUB_ONLY
    int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size) STUB_ONLY
    #endif*/

}