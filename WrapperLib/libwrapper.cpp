extern "C" {
#define _GNU_SOURCE
#include <signal.h>
#include <sys/prctl.h> // for arch_prctl (on Linux)
#include <asm/prctl.h>

#include <unistd.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <tirpc/rpc/auth.h>
#include <tirpc/rpc/auth_unix.h>
#include <tirpc/rpc/clnt.h>


#pragma once
#include <stdint.h>

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FIXED_ADDR ((void *)0x700000000000UL)
#define MAX_THREADS 100


#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>


#define MAX_STACK_FRAMES 64

void print_stack(void)
{
    void *buffer[MAX_STACK_FRAMES];
    int nptrs = backtrace(buffer, MAX_STACK_FRAMES);

    if (nptrs == 0) {
        printf("  <empty stack>\n");
        return;
    }

    char **symbols = backtrace_symbols(buffer, nptrs);
    if (!symbols) {
        perror("backtrace_symbols");
        return;
    }

    printf("==== Stack trace (%d frames) ====\n", nptrs);

    for (int i = 0; i < nptrs; i++) {
        printf("  [%02d] %s\n", i, symbols[i]);
    }

    printf("=================================\n");

    free(symbols);
}




typedef struct {
    uint32_t thread_id;
    uint32_t counter;
} countTable;

#define COUNTER_TABLE ((countTable *)FIXED_ADDR)

/* MPK-protected pkey for TCB region (set in libmpk_init.so) */
int pk_counter = 1;

/* -------------------------------------------------------------------------- */
/* Thread-local state                                                         */
/* -------------------------------------------------------------------------- */

static __thread uint32_t cached_tid = 0;
static __thread int slot_index = -1;

static inline uint32_t gettid_fast(void) {
    if (cached_tid == 0) {
        cached_tid = (uint32_t)syscall(SYS_gettid);
    }
    return cached_tid;
}

/* -------------------------------------------------------------------------- */
/* PKRU helpers                                                                */
/* -------------------------------------------------------------------------- */

#define PKEY_TCB 1   // FIXED_ADDR uses pkey 1

static inline uint32_t rdpkru(void) {
    uint32_t eax, edx;
    __asm__ volatile(".byte 0x0f,0x01,0xee"
                     : "=a"(eax), "=d"(edx)
                     : "c"(0));
    return eax;
}

static inline void wrpkru(uint32_t pkru) {
    uint32_t ecx = 0, edx = 0;
    __asm__ volatile(".byte 0x0f,0x01,0xef"
                     :
                     : "a"(pkru), "c"(ecx), "d"(edx));
}

static inline void enable_write_tcb(void) {
    uint32_t pkru = rdpkru();
    pkru &= ~(3u << (2 * PKEY_TCB));   // clear AD + WD bits for pkey 1
    wrpkru(pkru);
}

static inline void disable_write_tcb(void) {
    uint32_t pkru = rdpkru();
    pkru |= (1u << (2 * PKEY_TCB + 1)); // set WD bit for pkey 1
    wrpkru(pkru);
}




/* -------------------------------------------------------------------------- */
/* Counter update API                                                          */
/* -------------------------------------------------------------------------- */

void mpk_entry_gate(void) {
    uint32_t tid = gettid_fast();

    // Enable write access to TCB
    enable_write_tcb();
  //  printf("mpk_entry_gate called for tid %u\n", tid);
   // print_stack();
    // Fast path: already know our slot
    if (slot_index >= 0) {
        COUNTER_TABLE[slot_index].counter += 1;
        disable_write_tcb();
        return;
    }

    // Slow path: find or allocate slot
    for (int i = 0; i < MAX_THREADS; i++) {

        // Existing entry for this thread
        if (COUNTER_TABLE[i].thread_id == tid) {
            slot_index = i;
            COUNTER_TABLE[i].counter += 1;
            disable_write_tcb();
            return;
        }

        // Free entry
        if (COUNTER_TABLE[i].thread_id == 0) {
            COUNTER_TABLE[i].thread_id = tid;
            COUNTER_TABLE[i].counter   = 1;
            slot_index = i;
            disable_write_tcb();
            return;
        }
    }

    // No free slot — just lock and return
    disable_write_tcb();
}

void mpk_exit_gate(void) {
    if (slot_index < 0)
        return;

    enable_write_tcb();

    COUNTER_TABLE[slot_index].counter = 0;
    COUNTER_TABLE[slot_index].thread_id = 0;
    slot_index = -1;

    disable_write_tcb();
}

// fputs, 1 puts, 1 open, 1 syscall, 1 fputc, 1 fwrite, 1 read, 1

void _Exit_wrapper(int status)
{
    typedef bool (*policy_fn_t)(int status);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "_Exit_policy");
    if (policy && !policy(status))
        abort();
    _Exit(status);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t __fbufsize_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__fbufsize_policy");
    if (policy && !policy(stream))
        abort();
    return __fbufsize(stream);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int __flbf_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__flbf_policy");
    if (policy && !policy(stream))
        abort();
    return __flbf(stream);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t __fpending_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__fpending_policy");
    if (policy && !policy(stream))
        abort();
    return __fpending(stream);
}

#include <stdio.h>
#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void __fpurge_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__fpurge_policy");
    if (policy && !policy(stream))
        abort();
    __fpurge(stream);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int __freadable_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__freadable_policy");
    if (policy && !policy(stream))
        abort();
    return __freadable(stream);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int __freading_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__freading_policy");
    if (policy && !policy(stream))
        abort();
    return __freading(stream);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int __fsetlocking_wrapper(FILE *stream, int type)
{
    typedef bool (*policy_fn_t)(FILE *stream, int type);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__fsetlocking_policy");
    if (policy && !policy(stream, type))
        abort();
    return __fsetlocking(stream, type);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int __fwritable_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__fwritable_policy");
    if (policy && !policy(stream))
        abort();
    return __fwritable(stream);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int __fwriting_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__fwriting_policy");
    if (policy && !policy(stream))
        abort();
    return __fwriting(stream);
}

#include <unistd.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void _exit_wrapper(int status)
{
    typedef bool (*policy_fn_t)(int status);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "_exit_policy");
    if (policy && !policy(status))
        abort();
    _exit(status);
}

#include <stdio.h>
#include <stdio_ext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void _flushlbf_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "_flushlbf_policy");
    if (policy && !policy())
        abort();
    _flushlbf();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long a64l_wrapper(const char *str64)
{
    typedef bool (*policy_fn_t)(const char *str64);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "a64l_policy");
    if (policy && !policy(str64))
        abort();
    return a64l(str64);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void abort_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "abort_policy");
    if (policy && !policy())
        abort();
    abort();
}

#include <stdlib.h>
#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int abs_wrapper(int j)
{
    typedef bool (*policy_fn_t)(int j);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "abs_policy");
    if (policy && !policy(j))
        abort();
    return abs(j);
}

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int accept_wrapper(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    //wakka printffrom accept\n");
    typedef bool (*policy_fn_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "accept_policy");
    if (policy && !policy(sockfd, addr, addrlen))
        abort();
    return accept(sockfd, addr, addrlen);
}

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int accept4_wrapper(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    //wakka printffrom accept4\n");
    typedef bool (*policy_fn_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "accept4_policy");
    if (policy && !policy(sockfd, addr, addrlen, flags))
        abort();
    return accept4(sockfd, addr, addrlen, flags);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int access_wrapper(const char *pathname, int mode)
{
    //wakka printffrom access\n");
    typedef bool (*policy_fn_t)(const char *pathname, int mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "access_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return access(pathname, mode);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int acct_wrapper(const char *filename)
{
    typedef bool (*policy_fn_t)(const char *filename);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "acct_policy");
    if (policy && !policy(filename))
        abort();
    return acct(filename);
}

#include <stdio.h>
#include <mntent.h>
#include <mntent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int addmntent_wrapper(FILE *stream, const struct mntent *mnt)
{
    typedef bool (*policy_fn_t)(FILE *stream, const struct mntent *mnt);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "addmntent_policy");
    if (policy && !policy(stream, mnt))
        abort();
    return addmntent(stream, mnt);
}

#include <fmtmsg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int addseverity_wrapper(int severity, const char *s)
{
    typedef bool (*policy_fn_t)(int severity, const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "addseverity_policy");
    if (policy && !policy(severity, s))
        abort();
    return addseverity(severity, s);
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int adjtime_wrapper(const struct timeval *delta, struct timeval *olddelta)
{
    typedef bool (*policy_fn_t)(const struct timeval *delta, struct timeval *olddelta);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "adjtime_policy");
    if (policy && !policy(delta, olddelta))
        abort();
    return adjtime(delta, olddelta);
}

#include <sys/timex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int adjtimex_wrapper(struct timex *buf)
{
    typedef bool (*policy_fn_t)(struct timex *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "adjtimex_policy");
    if (policy && !policy(buf))
        abort();
    return adjtimex(buf);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int aio_cancel_wrapper(int fd, struct aiocb *aiocbp)
{
    typedef bool (*policy_fn_t)(int fd, struct aiocb *aiocbp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_cancel_policy");
    if (policy && !policy(fd, aiocbp))
        abort();
    return aio_cancel(fd, aiocbp);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int aio_error_wrapper(const struct aiocb *aiocbp)
{
    typedef bool (*policy_fn_t)(const struct aiocb *aiocbp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_error_policy");
    if (policy && !policy(aiocbp))
        abort();
    return aio_error(aiocbp);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int aio_fsync_wrapper(int op, struct aiocb *aiocbp)
{
    typedef bool (*policy_fn_t)(int op, struct aiocb *aiocbp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_fsync_policy");
    if (policy && !policy(op, aiocbp))
        abort();
    return aio_fsync(op, aiocbp);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void aio_init_wrapper(const struct aioinit *init)
{
    typedef bool (*policy_fn_t)(const struct aioinit *init);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_init_policy");
    if (policy && !policy(init))
        abort();
    aio_init(init);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int aio_read_wrapper(struct aiocb *aiocbp)
{
    typedef bool (*policy_fn_t)(struct aiocb *aiocbp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_read_policy");
    if (policy && !policy(aiocbp))
        abort();
    return aio_read(aiocbp);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t aio_return_wrapper(struct aiocb *aiocbp)
{
    typedef bool (*policy_fn_t)(struct aiocb *aiocbp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_return_policy");
    if (policy && !policy(aiocbp))
        abort();
    return aio_return(aiocbp);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int aio_suspend_wrapper(const struct aiocb *const aiocb_list[], int nitems, const struct timespec *timeout)
{
    typedef bool (*policy_fn_t)(const struct aiocb *const aiocb_list[], int nitems, const struct timespec *timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_suspend_policy");
    if (policy && !policy(aiocb_list, nitems, timeout))
        abort();
    return aio_suspend(aiocb_list, nitems, timeout);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int aio_write_wrapper(struct aiocb *aiocbp)
{
    typedef bool (*policy_fn_t)(struct aiocb *aiocbp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aio_write_policy");
    if (policy && !policy(aiocbp))
        abort();
    return aio_write(aiocbp);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned int alarm_wrapper(unsigned int seconds)
{
    typedef bool (*policy_fn_t)(unsigned int seconds);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "alarm_policy");
    if (policy && !policy(seconds))
        abort();
    return alarm(seconds);
}

#include <stdlib.h>
#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *aligned_alloc_wrapper(size_t alignment, size_t size)
{
    typedef bool (*policy_fn_t)(size_t alignment, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "aligned_alloc_policy");
    if (policy && !policy(alignment, size))
        abort();
    return aligned_alloc(alignment, size);
}

#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int alphasort_wrapper(const struct dirent **a, const struct dirent **b)
{
    typedef bool (*policy_fn_t)(const struct dirent **a, const struct dirent **b);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "alphasort_policy");
    if (policy && !policy(a, b))
        abort();
    return alphasort(a, b);
}

// #include <asm/prctl.h>
// #include <sys/prctl.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int arch_prctl_wrapper(int code, unsigned long addr)
// {
//     typedef bool (*policy_fn_t)(int code, unsigned long addr);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "arch_prctl_policy");
//     if (policy && !policy(code, addr))
//         abort();
//     return arch_prctl(code, addr);
// }

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_add_wrapper(char **argz, size_t *argz_len, const char *str)
{
    typedef bool (*policy_fn_t)(char **argz, size_t *argz_len, const char *str);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_add_policy");
    if (policy && !policy(argz, argz_len, str))
        abort();
    return argz_add(argz, argz_len, str);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_add_sep_wrapper(char **argz, size_t *argz_len, const char *str, int delim)
{
    typedef bool (*policy_fn_t)(char **argz, size_t *argz_len, const char *str, int delim);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_add_sep_policy");
    if (policy && !policy(argz, argz_len, str, delim))
        abort();
    return argz_add_sep(argz, argz_len, str, delim);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_append_wrapper(char **argz, size_t *argz_len, const char *buf, size_t buf_len)
{
    typedef bool (*policy_fn_t)(char **argz, size_t *argz_len, const char *buf, size_t buf_len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_append_policy");
    if (policy && !policy(argz, argz_len, buf, buf_len))
        abort();
    return argz_append(argz, argz_len, buf, buf_len);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t argz_count_wrapper(const char *argz, size_t argz_len)
{
    typedef bool (*policy_fn_t)(const char *argz, size_t argz_len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_count_policy");
    if (policy && !policy(argz, argz_len))
        abort();
    return argz_count(argz, argz_len);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_create_wrapper(char *const argv[], char **argz, size_t *argz_len)
{
    typedef bool (*policy_fn_t)(char *const argv[], char **argz, size_t *argz_len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_create_policy");
    if (policy && !policy(argv, argz, argz_len))
        abort();
    return argz_create(argv, argz, argz_len);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_create_sep_wrapper(const char *str, int sep, char **argz, size_t *argz_len)
{
    typedef bool (*policy_fn_t)(const char *str, int sep, char **argz, size_t *argz_len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_create_sep_policy");
    if (policy && !policy(str, sep, argz, argz_len))
        abort();
    return argz_create_sep(str, sep, argz, argz_len);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void argz_delete_wrapper(char **argz, size_t *argz_len, char *entry)
{
    typedef bool (*policy_fn_t)(char **argz, size_t *argz_len, char *entry);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_delete_policy");
    if (policy && !policy(argz, argz_len, entry))
        abort();
    argz_delete(argz, argz_len, entry);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void argz_extract_wrapper(const char *argz, size_t argz_len, char **argv)
{
    typedef bool (*policy_fn_t)(const char *argz, size_t argz_len, char **argv);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_extract_policy");
    if (policy && !policy(argz, argz_len, argv))
        abort();
    argz_extract(argz, argz_len, argv);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_insert_wrapper(char **argz, size_t *argz_len, char *before, const char *entry)
{
    typedef bool (*policy_fn_t)(char **argz, size_t *argz_len, char *before, const char *entry);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_insert_policy");
    if (policy && !policy(argz, argz_len, before, entry))
        abort();
    return argz_insert(argz, argz_len, before, entry);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *argz_next_wrapper(const char *argz, size_t argz_len, const char *entry)
{
    typedef bool (*policy_fn_t)(const char *argz, size_t argz_len, const char *entry);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_next_policy");
    if (policy && !policy(argz, argz_len, entry))
        abort();
    return argz_next(argz, argz_len, entry);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t argz_replace_wrapper(char **argz, size_t *argz_len, const char *str, const char *with, unsigned int *replace_count)
{
    typedef bool (*policy_fn_t)(char **argz, size_t *argz_len, const char *str, const char *with, unsigned int *replace_count);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_replace_policy");
    if (policy && !policy(argz, argz_len, str, with, replace_count))
        abort();
    return argz_replace(argz, argz_len, str, with, replace_count);
}

#include <argz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void argz_stringify_wrapper(char *argz, size_t len, int sep)
{
    typedef bool (*policy_fn_t)(char *argz, size_t len, int sep);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "argz_stringify_policy");
    if (policy && !policy(argz, len, sep))
        abort();
    argz_stringify(argz, len, sep);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *asctime_wrapper(const struct tm *tm)
{
    typedef bool (*policy_fn_t)(const struct tm *tm);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "asctime_policy");
    if (policy && !policy(tm))
        abort();
    return asctime(tm);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *asctime_r_wrapper(const struct tm *tm, char *buf)
{
    typedef bool (*policy_fn_t)(const struct tm *tm, char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "asctime_r_policy");
    if (policy && !policy(tm, buf))
        abort();
    return asctime_r(tm, buf);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int asprintf_wrapper(char **strp, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    typedef bool (*policy_fn_t)(char **, const char *);

    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "asprintf_policy");
    if (policy && !policy(strp, fmt))
    {
        va_end(args);
        abort();
    }

    int ret = vasprintf(strp, fmt, args);
    va_end(args);
    return ret;
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double atof_wrapper(const char *nptr)
{
    typedef bool (*policy_fn_t)(const char *nptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "atof_policy");
    if (policy && !policy(nptr))
        abort();
    return atof(nptr);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int atoi_wrapper(const char *nptr)
{
    typedef bool (*policy_fn_t)(const char *nptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "atoi_policy");
    if (policy && !policy(nptr))
        abort();
    return atoi(nptr);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long atol_wrapper(const char *nptr)
{
    typedef bool (*policy_fn_t)(const char *nptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "atol_policy");
    if (policy && !policy(nptr))
        abort();
    return atol(nptr);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long long atoll_wrapper(const char *nptr)
{
    typedef bool (*policy_fn_t)(const char *nptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "atoll_policy");
    if (policy && !policy(nptr))
        abort();
    return atoll(nptr);
}

//#include <tirpc/auth.h>
// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

AUTH *authnone_create_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "authnone_create_policy");
    if (policy && !policy())
        abort();
    return authnone_create();
}

//// #include <rpc/auth.h>
// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

#include <sys/types.h>    // uid_t, gid_t

AUTH *authunix_create_wrapper(char *host, uid_t uid, gid_t gid, int len, uid_t *aup_gids)
{
    typedef bool (*policy_fn_t)(char *host, uid_t uid, gid_t gid, int len, uid_t *aup_gids);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "authunix_create_policy");

    if (policy && !policy(host, uid, gid, len, aup_gids))
        abort();

    return authunix_create(host, uid, gid, len, aup_gids);
}

//// #include <rpc/auth.h>
// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

AUTH *authunix_create_default_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "authunix_create_default_policy");
    if (policy && !policy())
        abort();
    return authunix_create_default();
}

#include <execinfo.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int backtrace_wrapper(void **buffer, int size)
{
    typedef bool (*policy_fn_t)(void **buffer, int size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "backtrace_policy");
    if (policy && !policy(buffer, size))
        abort();
    return backtrace(buffer, size);
}

#include <execinfo.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char **backtrace_symbols_wrapper(void *const *buffer, int size)
{
    typedef bool (*policy_fn_t)(void *const *buffer, int size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "backtrace_symbols_policy");
    if (policy && !policy(buffer, size))
        abort();
    return backtrace_symbols(buffer, size);
}

#include <execinfo.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void backtrace_symbols_fd_wrapper(void *const *buffer, int size, int fd)
{
    typedef bool (*policy_fn_t)(void *const *buffer, int size, int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "backtrace_symbols_fd_policy");
    if (policy && !policy(buffer, size, fd))
        abort();
    backtrace_symbols_fd(buffer, size, fd);
}

#include <libgen.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *basename_wrapper(char *path)
{
    typedef bool (*policy_fn_t)(char *path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "basename_policy");
    if (policy && !policy(path))
        abort();
    return basename(path);
}

#include <strings.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int bcmp_wrapper(const void *s1, const void *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const void *s1, const void *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bcmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return bcmp(s1, s2, n);
}

#include <strings.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void bcopy_wrapper(const void *src, void *dest, size_t n)
{
    typedef bool (*policy_fn_t)(const void *src, void *dest, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bcopy_policy");
    if (policy && !policy(src, dest, n))
        abort();
    bcopy(src, dest, n);
}

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int bdflush_wrapper(int func, long *address)
// {
//     typedef bool (*policy_fn_t)(int func, long *address);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bdflush_policy");
//     if (policy && !policy(func, address))
//         abort();
//     return bdflush(func, address);
// }

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int bind_wrapper(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    //wakka printffrom bind\n");
    typedef bool (*policy_fn_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bind_policy");
    if (policy && !policy(sockfd, addr, addrlen))
        abort();
    return bind(sockfd, addr, addrlen);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *bind_textdomain_codeset_wrapper(const char *domainname, const char *codeset)
{
    typedef bool (*policy_fn_t)(const char *domainname, const char *codeset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bind_textdomain_codeset_policy");
    if (policy && !policy(domainname, codeset))
        abort();
    return bind_textdomain_codeset(domainname, codeset);
}

#include <sys/types.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int bindresvport_wrapper(int sockfd, struct sockaddr_in *sin)
{
    typedef bool (*policy_fn_t)(int sockfd, struct sockaddr_in *sin);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bindresvport_policy");
    if (policy && !policy(sockfd, sin))
        abort();
    return bindresvport(sockfd, sin);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *bindtextdomain_wrapper(const char *domainname, const char *dirname)
{
    //wakka printffrom bindtextdomain\n");
    //wakka printfdomainname : %s dirname = %s\n", domainname, dirname);
    typedef bool (*policy_fn_t)(const char *domainname, const char *dirname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bindtextdomain_policy");
    if (policy && !policy(domainname, dirname))
        abort();
    return bindtextdomain(domainname, dirname);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int brk_wrapper(void *addr)
{
    typedef bool (*policy_fn_t)(void *addr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "brk_policy");
    if (policy && !policy(addr))
        abort();
    return brk(addr);
}

// #include <signal.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// sighandler_t bsd_signal_wrapper(int signum, sighandler_t handler)
// {
//     typedef bool (*policy_fn_t)(int signum, sighandler_t handler);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bsd_signal_policy");
//     if (policy && !policy(signum, handler))
//         abort();
//     return bsd_signal(signum, handler);
// }

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *bsearch_wrapper(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bsearch_policy");
    if (policy && !policy(key, base, nmemb, size, compar))
        abort();
    return bsearch(key, base, nmemb, size, compar);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t btowc_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "btowc_policy");
    if (policy && !policy(c))
        abort();
    return btowc(c);
}

#include <strings.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void bzero_wrapper(void *s, size_t n)
{
    typedef bool (*policy_fn_t)(void *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "bzero_policy");
    if (policy && !policy(s, n))
        abort();
    bzero(s, n);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *calloc_wrapper(size_t nmemb, size_t size)
{
    typedef bool (*policy_fn_t)(size_t nmemb, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "calloc_policy");
    if (policy && !policy(nmemb, size))
        abort();
    return calloc(nmemb, size);
}

// // // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int callrpc_wrapper(char *host, unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out)
// {
//     typedef bool (*policy_fn_t)(char *host, unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "callrpc_policy");
//     if (policy && !policy(host, prognum, versnum, procnum, inproc, in, outproc, out))
//         abort();
//     return callrpc(host, prognum, versnum, procnum, inproc, in, outproc, out);
// }

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *canonicalize_file_name_wrapper(const char *path)
{
    typedef bool (*policy_fn_t)(const char *path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "canonicalize_file_name_policy");
    if (policy && !policy(path))
        abort();
    return canonicalize_file_name(path);
}

// #include <sys/capability.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int capget_wrapper(cap_user_header_t hdrp, cap_user_data_t datap) {
//     typedef bool (*policy_fn_t)(cap_user_header_t hdrp, cap_user_data_t datap);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "capget_policy");
//     if(policy && !policy(hdrp, datap)) abort();
//     return capget(hdrp, datap);
// }

// #include <sys/capability.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int capset_wrapper(cap_user_header_t hdrp, const cap_user_data_t datap) {
//     typedef bool (*policy_fn_t)(cap_user_header_t hdrp, const cap_user_data_t datap);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "capset_policy");
//     if(policy && !policy(hdrp, datap)) abort();
//     return capset(hdrp, datap);
// }

#include <nl_types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int catclose_wrapper(nl_catd catalog)
{
    typedef bool (*policy_fn_t)(nl_catd catalog);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "catclose_policy");
    if (policy && !policy(catalog))
        abort();
    return catclose(catalog);
}

#include <nl_types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *catgets_wrapper(nl_catd catalog, int set_number, int message_number, const char *message)
{
    typedef bool (*policy_fn_t)(nl_catd catalog, int set_number, int message_number, const char *message);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "catgets_policy");
    if (policy && !policy(catalog, set_number, message_number, message))
        abort();
    return catgets(catalog, set_number, message_number, message);
}

#include <nl_types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

nl_catd catopen_wrapper(const char *name, int flag)
{
    typedef bool (*policy_fn_t)(const char *name, int flag);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "catopen_policy");
    if (policy && !policy(name, flag))
        abort();
    return catopen(name, flag);
}

//// #include <rpc/des_crypt.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int cbc_crypt_wrapper(char *key, char *data, unsigned datalen, unsigned mode, char *ivec)
// {
//     typedef bool (*policy_fn_t)(char *key, char *data, unsigned datalen, unsigned mode, char *ivec);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cbc_crypt_policy");
//     if (policy && !policy(key, data, datalen, mode, ivec))
//         abort();
//     return cbc_crypt(key, data, datalen, mode, ivec);
// }

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

speed_t cfgetispeed_wrapper(const struct termios *termios_p)
{
    typedef bool (*policy_fn_t)(const struct termios *termios_p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfgetispeed_policy");
    if (policy && !policy(termios_p))
        abort();
    return cfgetispeed(termios_p);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

speed_t cfgetospeed_wrapper(const struct termios *termios_p)
{
    //wakka printffrom cfgetospeed\n");
    typedef bool (*policy_fn_t)(const struct termios *termios_p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfgetospeed_policy");
    if (policy && !policy(termios_p))
        abort();
    return cfgetospeed(termios_p);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void cfmakeraw_wrapper(struct termios *termios_p)
{
    typedef bool (*policy_fn_t)(struct termios *termios_p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfmakeraw_policy");
    if (policy && !policy(termios_p))
        abort();
    cfmakeraw(termios_p);
}

// #include <stdlib.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int cfree_wrapper(void *ptr)
// {
//     typedef bool (*policy_fn_t)(void *ptr);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfree_policy");
//     if (policy && !policy(ptr))
//         abort();
//     return cfree(ptr);
// }

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int cfsetispeed_wrapper(struct termios *termios_p, speed_t speed)
{
    typedef bool (*policy_fn_t)(struct termios *termios_p, speed_t speed);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfsetispeed_policy");
    if (policy && !policy(termios_p, speed))
        abort();
    return cfsetispeed(termios_p, speed);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int cfsetospeed_wrapper(struct termios *termios_p, speed_t speed)
{
    typedef bool (*policy_fn_t)(struct termios *termios_p, speed_t speed);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfsetospeed_policy");
    if (policy && !policy(termios_p, speed))
        abort();
    return cfsetospeed(termios_p, speed);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int cfsetspeed_wrapper(struct termios *termios_p, speed_t speed)
{
    typedef bool (*policy_fn_t)(struct termios *termios_p, speed_t speed);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cfsetspeed_policy");
    if (policy && !policy(termios_p, speed))
        abort();
    return cfsetspeed(termios_p, speed);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int chdir_wrapper(const char *path)
{
    typedef bool (*policy_fn_t)(const char *path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "chdir_policy");
    if (policy && !policy(path))
        abort();
    return chdir(path);
}

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int chmod_wrapper(const char *pathname, mode_t mode)
{
    typedef bool (*policy_fn_t)(const char *pathname, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "chmod_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return chmod(pathname, mode);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int chown_wrapper(const char *pathname, uid_t owner, gid_t group)
{
    typedef bool (*policy_fn_t)(const char *pathname, uid_t owner, gid_t group);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "chown_policy");
    if (policy && !policy(pathname, owner, group))
        abort();
    return chown(pathname, owner, group);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int chroot_wrapper(const char *path)
{
    typedef bool (*policy_fn_t)(const char *path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "chroot_policy");
    if (policy && !policy(path))
        abort();
    return chroot(path);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clearenv_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clearenv_policy");
    if (policy && !policy())
        abort();
    return clearenv();
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void clearerr_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clearerr_policy");
    if (policy && !policy(stream))
        abort();
    clearerr(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void clearerr_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clearerr_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    clearerr_unlocked(stream);
}

// // // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// enum clnt_stat clnt_broadcast_wrapper(unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out, resultproc_t eachresult)
// {
//     typedef bool (*policy_fn_t)(unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out, resultproc_t eachresult);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_broadcast_policy");
//     if (policy && !policy(prognum, versnum, procnum, inproc, in, outproc, out, eachresult))
//         abort();
//     return clnt_broadcast(prognum, versnum, procnum, inproc, in, outproc, out, eachresult);
// }

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

CLIENT *clnt_create_wrapper(char *host, unsigned long prog, unsigned long vers, char *proto)
{
    typedef bool (*policy_fn_t)(char *host, unsigned long prog, unsigned long vers, char *proto);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_create_policy");
    if (policy && !policy(host, prog, vers, proto))
        abort();
    return clnt_create(host, prog, vers, proto);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void clnt_pcreateerror_wrapper(char *s)
{
    typedef bool (*policy_fn_t)(char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_pcreateerror_policy");
    if (policy && !policy(s))
        abort();
    clnt_pcreateerror(s);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void clnt_perrno_wrapper(enum clnt_stat stat)
{
    typedef bool (*policy_fn_t)(enum clnt_stat stat);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_perrno_policy");
    if (policy && !policy(stat))
        abort();
    clnt_perrno(stat);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void clnt_perror_wrapper(CLIENT *clnt, char *s)
{
    typedef bool (*policy_fn_t)(CLIENT *clnt, char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_perror_policy");
    if (policy && !policy(clnt, s))
        abort();
    clnt_perror(clnt, s);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *clnt_spcreateerror_wrapper(char *s)
{
    typedef bool (*policy_fn_t)(char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_spcreateerror_policy");
    if (policy && !policy(s))
        abort();
    return clnt_spcreateerror(s);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *clnt_sperrno_wrapper(enum clnt_stat stat)
{
    typedef bool (*policy_fn_t)(enum clnt_stat stat);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_sperrno_policy");
    if (policy && !policy(stat))
        abort();
    return clnt_sperrno(stat);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *clnt_sperror_wrapper(CLIENT *rpch, char *s)
{
    typedef bool (*policy_fn_t)(CLIENT *rpch, char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnt_sperror_policy");
    if (policy && !policy(rpch, s))
        abort();
    return clnt_sperror(rpch, s);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

CLIENT *clntraw_create_wrapper(unsigned long prognum, unsigned long versnum)
{
    typedef bool (*policy_fn_t)(unsigned long prognum, unsigned long versnum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clntraw_create_policy");
    if (policy && !policy(prognum, versnum))
        abort();
    return clntraw_create(prognum, versnum);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

CLIENT *clnttcp_create_wrapper(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, int *sockp, unsigned int sendsz, unsigned int recvsz)
{
    typedef bool (*policy_fn_t)(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, int *sockp, unsigned int sendsz, unsigned int recvsz);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clnttcp_create_policy");
    if (policy && !policy(addr, prognum, versnum, sockp, sendsz, recvsz))
        abort();
    return clnttcp_create(addr, prognum, versnum, sockp, sendsz, recvsz);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

CLIENT *clntudp_bufcreate_wrapper(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, struct timeval wait, int *sockp, unsigned int sendsize, unsigned int recosize)
{
    typedef bool (*policy_fn_t)(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, struct timeval wait, int *sockp, unsigned int sendsize, unsigned int recosize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clntudp_bufcreate_policy");
    if (policy && !policy(addr, prognum, versnum, wait, sockp, sendsize, recosize))
        abort();
    return clntudp_bufcreate(addr, prognum, versnum, wait, sockp, sendsize, recosize);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

CLIENT *clntudp_create_wrapper(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, struct timeval wait, int *sockp)
{
    typedef bool (*policy_fn_t)(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, struct timeval wait, int *sockp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clntudp_create_policy");
    if (policy && !policy(addr, prognum, versnum, wait, sockp))
        abort();
    return clntudp_create(addr, prognum, versnum, wait, sockp);
}

// Could not parse: clock_t clock(void)

#include <sys/timex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clock_adjtime_wrapper(clockid_t clk_id, struct timex *buf)
{
    typedef bool (*policy_fn_t)(clockid_t clk_id, struct timex *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clock_adjtime_policy");
    if (policy && !policy(clk_id, buf))
        abort();
    return clock_adjtime(clk_id, buf);
}

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clock_getcpuclockid_wrapper(pid_t pid, clockid_t *clockid)
{
    typedef bool (*policy_fn_t)(pid_t pid, clockid_t *clockid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clock_getcpuclockid_policy");
    if (policy && !policy(pid, clockid))
        abort();
    return clock_getcpuclockid(pid, clockid);
}

#include <time.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clock_getres_wrapper(clockid_t clockid, struct timespec *res)
{
    typedef bool (*policy_fn_t)(clockid_t clockid, struct timespec *res);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clock_getres_policy");
    if (policy && !policy(clockid, res))
        abort();
    return clock_getres(clockid, res);
}

#include <time.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clock_gettime_wrapper(clockid_t clockid, struct timespec *tp)
{
    typedef bool (*policy_fn_t)(clockid_t clockid, struct timespec *tp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clock_gettime_policy");
    if (policy && !policy(clockid, tp))
        abort();
    return clock_gettime(clockid, tp);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clock_nanosleep_wrapper(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain)
{
    typedef bool (*policy_fn_t)(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clock_nanosleep_policy");
    if (policy && !policy(clockid, flags, request, remain))
        abort();
    return clock_nanosleep(clockid, flags, request, remain);
}

#include <time.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int clock_settime_wrapper(clockid_t clockid, const struct timespec *tp)
{
    typedef bool (*policy_fn_t)(clockid_t clockid, const struct timespec *tp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "clock_settime_policy");
    if (policy && !policy(clockid, tp))
        abort();
    return clock_settime(clockid, tp);
}

#include <sched.h>
#include <syscall.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

long clone_wrapper(unsigned long flags, void *stack,
                   int *parent_tid, int *child_tid,
                   unsigned long tls)
{
    typedef bool (*policy_fn_t)(unsigned long flags, void *stack,
                                int *parent_tid, int *child_tid,
                                unsigned long tls);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "clone_policy");

    if (policy && !policy(flags, stack, parent_tid, child_tid, tls))
        abort();

    // Kernel ABI: clone(flags, stack, parent_tid, tls, child_tid)
    return syscall(SYS_clone, flags, stack, parent_tid, tls, child_tid);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int close_wrapper(int fd)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);

    FILE *log = fopen("fclose.txt", "a");
    if (log == NULL)
    {
        // fallback if log file cannot be opened
        return close(fd);
    }

    if (len != -1)
    {
        buf[len] = '\0';
        fprintf(log, "from close: fd=%d, target=%s\n", fd, buf);
    }
    else
    {
        fprintf(log, "from close: fd=%d, target=unknown (fd may already be closed)\n", fd);
    }

    fclose(log);
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "close_policy");
    if (policy && !policy(fd))
        abort();
    return close(fd);
}

#include <sys/types.h>
#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int closedir_wrapper(DIR *dirp)
{
    //wakka printffrom closedir\n");
    typedef bool (*policy_fn_t)(DIR *dirp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "closedir_policy");
    if (policy && !policy(dirp))
        abort();
    return closedir(dirp);
}

#include <syslog.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void closelog_wrapper(void)
{
    //wakka printffrom closelog\n");
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "closelog_policy");
    if (policy && !policy())
        abort();
    closelog();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t confstr_wrapper(int name, char *buf, size_t len)
{
    typedef bool (*policy_fn_t)(int name, char *buf, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "confstr_policy");
    if (policy && !policy(name, buf, len))
        abort();
    return confstr(name, buf, len);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int connect_wrapper(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    //wakka printffrom connect\n");
    typedef bool (*policy_fn_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "connect_policy");
    if (policy && !policy(sockfd, addr, addrlen))
        abort();
    return connect(sockfd, addr, addrlen);
}

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t copy_file_range_wrapper(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
{
    typedef bool (*policy_fn_t)(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "copy_file_range_policy");
    if (policy && !policy(fd_in, off_in, fd_out, off_out, len, flags))
        abort();
    return copy_file_range(fd_in, off_in, fd_out, off_out, len, flags);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double copysign_wrapper(double x, double y)
{
    typedef bool (*policy_fn_t)(double x, double y);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "copysign_policy");
    if (policy && !policy(x, y))
        abort();
    return copysign(x, y);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

float copysignf_wrapper(float x, float y)
{
    typedef bool (*policy_fn_t)(float x, float y);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "copysignf_policy");
    if (policy && !policy(x, y))
        abort();
    return copysignf(x, y);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long double copysignl_wrapper(long double x, long double y)
{
    typedef bool (*policy_fn_t)(long double x, long double y);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "copysignl_policy");
    if (policy && !policy(x, y))
        abort();
    return copysignl(x, y);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int creat_wrapper(const char *pathname, mode_t mode)
{
    typedef bool (*policy_fn_t)(const char *pathname, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "creat_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return creat(pathname, mode);
}

// #include <linux/module.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// caddr_t create_module_wrapper(const char *name, size_t size)
// {
//     typedef bool (*policy_fn_t)(const char *name, size_t size);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "create_module_policy");
//     if (policy && !policy(name, size))
//         abort();
//     return create_module(name, size);
// }

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ctermid_wrapper(char *s)
{
    typedef bool (*policy_fn_t)(char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ctermid_policy");
    if (policy && !policy(s))
        abort();
    return ctermid(s);
}

// #include <time.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// #include <time.h>

// char *ctime_wrapper(const struct tm *tm)
// {
//     typedef bool (*policy_fn_t)(const struct tm *);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ctime_policy");
//     if (policy && !policy(tm))
//         abort();

//     struct tm tm_copy = *tm;   // make it non-const for mktime()
//     time_t t = mktime(&tm_copy);

//     return ctime(&t);          // correct type
// }


#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

#include <time.h>

char *ctime_wrapper(const struct tm *tmval)
{
    typedef bool (*policy_fn_t)(const struct tm *);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ctime_policy");
    if (policy && !policy(tmval))
        abort();

    time_t t = mktime((struct tm *)tmval);  // must cast away const for mktime
    return ctime(&t);
}


#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *cuserid_wrapper(char *string)
{
    typedef bool (*policy_fn_t)(char *string);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "cuserid_policy");
    if (policy && !policy(string))
        abort();
    return cuserid(string);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int daemon_wrapper(int nochdir, int noclose)
{
    typedef bool (*policy_fn_t)(int nochdir, int noclose);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "daemon_policy");
    if (policy && !policy(nochdir, noclose))
        abort();
    return daemon(nochdir, noclose);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *dcgettext_wrapper(const char *domainname, const char *msgid, int category)
{
    typedef bool (*policy_fn_t)(const char *domainname, const char *msgid, int category);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dcgettext_policy");
    if (policy && !policy(domainname, msgid, category))
        abort();
    return dcgettext(domainname, msgid, category);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *dcngettext_wrapper(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category)
{
    typedef bool (*policy_fn_t)(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dcngettext_policy");
    if (policy && !policy(domainname, msgid, msgid_plural, n, category))
        abort();
    return dcngettext(domainname, msgid, msgid_plural, n, category);
}

// #include <unistd.h>
// #include <sys/syscall.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int delete_module_wrapper(const char *name, int flags)
// {
//     typedef bool (*policy_fn_t)(const char *name, int flags);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "delete_module_policy");
//     if (policy && !policy(name, flags))
//         abort();
//     return delete_module(name, flags);
// }

//// #include <rpc/des_crypt.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void des_setparity_wrapper(char *key)
// {
//     typedef bool (*policy_fn_t)(char *key);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "des_setparity_policy");
//     if (policy && !policy(key))
//         abort();
//     des_setparity(key);
// }

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *dgettext_wrapper(const char *domainname, const char *msgid)
{
    typedef bool (*policy_fn_t)(const char *domainname, const char *msgid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dgettext_policy");
    if (policy && !policy(domainname, msgid))
        abort();
    return dgettext(domainname, msgid);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double difftime_wrapper(time_t time1, time_t time0)
{
    typedef bool (*policy_fn_t)(time_t time1, time_t time0);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "difftime_policy");
    if (policy && !policy(time1, time0))
        abort();
    return difftime(time1, time0);
}

#include <sys/types.h>
#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dirfd_wrapper(DIR *dirp)
{
    typedef bool (*policy_fn_t)(DIR *dirp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dirfd_policy");
    if (policy && !policy(dirp))
        abort();
    return dirfd(dirp);
}

#include <libgen.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *dirname_wrapper(char *path)
{
    typedef bool (*policy_fn_t)(char *path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dirname_policy");
    if (policy && !policy(path))
        abort();
    return dirname(path);
}

// Could not parse: div_t div(int numerator, int denominator)

#include <link.h>
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dl_iterate_phdr_wrapper(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data)
{
    typedef bool (*policy_fn_t)(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dl_iterate_phdr_policy");
    if (policy && !policy(callback, data))
        abort();
    return dl_iterate_phdr(callback, data);
}

#include <dlfcn.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dladdr_wrapper(void *addr, Dl_info *info)
{
    typedef bool (*policy_fn_t)(void *addr, Dl_info *info);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dladdr_policy");
    if (policy && !policy(addr, info))
        abort();
    return dladdr(addr, info);
}

#include <dlfcn.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dladdr1_wrapper(void *addr, Dl_info *info, void **extra_info, int flags)
{
    typedef bool (*policy_fn_t)(void *addr, Dl_info *info, void **extra_info, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dladdr1_policy");
    if (policy && !policy(addr, info, extra_info, flags))
        abort();
    return dladdr1(addr, info, extra_info, flags);
}

#include <dlfcn.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <gnu/lib-names.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dlclose_wrapper(void *handle)
{
    typedef bool (*policy_fn_t)(void *handle);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlclose_policy");
    if (policy && !policy(handle))
        abort();
    return dlclose(handle);
}

#include <dlfcn.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *dlerror_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlerror_policy");
    if (policy && !policy())
        abort();
    return dlerror();
}

#include <link.h>
#include <dlfcn.h>
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dlinfo_wrapper(void *handle, int request, void *info)
{
    typedef bool (*policy_fn_t)(void *handle, int request, void *info);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlinfo_policy");
    if (policy && !policy(handle, request, info))
        abort();
    return dlinfo(handle, request, info);
}

#include <dlfcn.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <gnu/lib-names.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *dlmopen_wrapper(Lmid_t lmid, const char *filename, int flags)
{
    typedef bool (*policy_fn_t)(Lmid_t lmid, const char *filename, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlmopen_policy");
    if (policy && !policy(lmid, filename, flags))
        abort();
    return dlmopen(lmid, filename, flags);
}

#include <dlfcn.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <gnu/lib-names.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *dlopen_wrapper(const char *filename, int flags)
{
    //wakka printfhello file from dlopen : %s\n", filename);
    typedef bool (*policy_fn_t)(const char *filename, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlopen_policy");
    if (policy && !policy(filename, flags))
        abort();
    return dlopen(filename, flags);
}

#include <dlfcn.h>
#include <dlfcn.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *dlsym_wrapper(void *handle, const char *symbol)
{
    typedef bool (*policy_fn_t)(void *handle, const char *symbol);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlsym_policy");
    if (policy && !policy(handle, symbol))
        abort();
    return dlsym(handle, symbol);
}

#include <dlfcn.h>
#include <dlfcn.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *dlvsym_wrapper(void *handle, char *symbol, char *version)
{
    typedef bool (*policy_fn_t)(void *handle, char *symbol, char *version);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dlvsym_policy");
    if (policy && !policy(handle, symbol, version))
        abort();
    return dlvsym(handle, symbol, version);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dn_comp_wrapper(const char *exp_dn, unsigned char *comp_dn, int length, unsigned char **dnptrs, unsigned char **lastdnptr)
{
    typedef bool (*policy_fn_t)(const char *exp_dn, unsigned char *comp_dn, int length, unsigned char **dnptrs, unsigned char **lastdnptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dn_comp_policy");
    if (policy && !policy(exp_dn, comp_dn, length, dnptrs, lastdnptr))
        abort();
    return dn_comp(exp_dn, comp_dn, length, dnptrs, lastdnptr);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dn_expand_wrapper(const unsigned char *msg, const unsigned char *eomorig, const unsigned char *comp_dn, char *exp_dn, int length)
{
    typedef bool (*policy_fn_t)(const unsigned char *msg, const unsigned char *eomorig, const unsigned char *comp_dn, char *exp_dn, int length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dn_expand_policy");
    if (policy && !policy(msg, eomorig, comp_dn, exp_dn, length))
        abort();
    return dn_expand(msg, eomorig, comp_dn, exp_dn, length);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *dngettext_wrapper(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n)
{
    typedef bool (*policy_fn_t)(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dngettext_policy");
    if (policy && !policy(domainname, msgid, msgid_plural, n))
        abort();
    return dngettext(domainname, msgid, msgid_plural, n);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dprintf_wrapper(int fd, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;

    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(int fd, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dprintf_policy");

    if (policy && !policy(fd, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vdprintf(fd, format, args); // <-- fix here
    va_end(args);
    return ret;
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double drand48_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "drand48_policy");
    if (policy && !policy())
        abort();
    return drand48();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int drand48_r_wrapper(struct drand48_data *buffer, double *result)
{
    typedef bool (*policy_fn_t)(struct drand48_data *buffer, double *result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "drand48_r_policy");
    if (policy && !policy(buffer, result))
        abort();
    return drand48_r(buffer, result);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dup_wrapper(int oldfd)
{
    typedef bool (*policy_fn_t)(int oldfd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dup_policy");
    if (policy && !policy(oldfd))
        abort();
    return dup(oldfd);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dup2_wrapper(int oldfd, int newfd)
{
    typedef bool (*policy_fn_t)(int oldfd, int newfd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dup2_policy");
    if (policy && !policy(oldfd, newfd))
        abort();
    return dup2(oldfd, newfd);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dup3_wrapper(int oldfd, int newfd, int flags)
{
    typedef bool (*policy_fn_t)(int oldfd, int newfd, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dup3_policy");
    if (policy && !policy(oldfd, newfd, flags))
        abort();
    return dup3(oldfd, newfd, flags);
}

#include <locale.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

locale_t duplocale_wrapper(locale_t locobj)
{
    typedef bool (*policy_fn_t)(locale_t locobj);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "duplocale_policy");
    if (policy && !policy(locobj))
        abort();
    return duplocale(locobj);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int dysize_wrapper(int year)
{
    typedef bool (*policy_fn_t)(int year);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "dysize_policy");
    if (policy && !policy(year))
        abort();
    return dysize(year);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int eaccess_wrapper(const char *pathname, int mode)
{
    typedef bool (*policy_fn_t)(const char *pathname, int mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "eaccess_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return eaccess(pathname, mode);
}

//// #include <rpc/des_crypt.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int ecb_crypt_wrapper(char *key, char *data, unsigned datalen, unsigned mode)
// {
//     typedef bool (*policy_fn_t)(char *key, char *data, unsigned datalen, unsigned mode);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ecb_crypt_policy");
//     if (policy && !policy(key, data, datalen, mode))
//         abort();
//     return ecb_crypt(key, data, datalen, mode);
// }

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ecvt_wrapper(double number, int ndigits, int *decpt, int *sign)
{
    typedef bool (*policy_fn_t)(double number, int ndigits, int *decpt, int *sign);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ecvt_policy");
    if (policy && !policy(number, ndigits, decpt, sign))
        abort();
    return ecvt(number, ndigits, decpt, sign);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ecvt_r_wrapper(double number, int ndigits, int *decpt, int *sign, char *buf, size_t len)
{
    typedef bool (*policy_fn_t)(double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ecvt_r_policy");
    if (policy && !policy(number, ndigits, decpt, sign, buf, len))
        abort();
    return ecvt_r(number, ndigits, decpt, sign, buf, len);
}

#include <aliases.h>

#include <aliases.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endaliasent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endaliasent_policy");
    if (policy && !policy())
        abort();
    endaliasent();
}

#include <fstab.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endfsent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endfsent_policy");
    if (policy && !policy())
        abort();
    endfsent();
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endgrent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endgrent_policy");
    if (policy && !policy())
        abort();
    endgrent();
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endhostent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endhostent_policy");
    if (policy && !policy())
        abort();
    endhostent();
}

#include <stdio.h>
#include <mntent.h>
#include <mntent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int endmntent_wrapper(FILE *streamp)
{
    typedef bool (*policy_fn_t)(FILE *streamp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endmntent_policy");
    if (policy && !policy(streamp))
        abort();
    return endmntent(streamp);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endnetent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endnetent_policy");
    if (policy && !policy())
        abort();
    endnetent();
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endnetgrent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endnetgrent_policy");
    if (policy && !policy())
        abort();
    endnetgrent();
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endprotoent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endprotoent_policy");
    if (policy && !policy())
        abort();
    endprotoent();
}

#include <sys/types.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endpwent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endpwent_policy");
    if (policy && !policy())
        abort();
    endpwent();
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endrpcent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endrpcent_policy");
    if (policy && !policy())
        abort();
    endrpcent();
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endservent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endservent_policy");
    if (policy && !policy())
        abort();
    endservent();
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endspent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endspent_policy");
    if (policy && !policy())
        abort();
    endspent();
}

#include <ttyent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int endttyent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endttyent_policy");
    if (policy && !policy())
        abort();
    return endttyent();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endusershell_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endusershell_policy");
    if (policy && !policy())
        abort();
    endusershell();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endutent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endutent_policy");
    if (policy && !policy())
        abort();
    endutent();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void endutxent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "endutxent_policy");
    if (policy && !policy())
        abort();
    endutxent();
}

#include <envz.h>
#include <stdio.h>
#include <stdlib.h>
#include <envz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t envz_add_wrapper(char **envz, size_t *envz_len, const char *name, const char *value)
{
    typedef bool (*policy_fn_t)(char **envz, size_t *envz_len, const char *name, const char *value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "envz_add_policy");
    if (policy && !policy(envz, envz_len, name, value))
        abort();
    return envz_add(envz, envz_len, name, value);
}

#include <envz.h>
#include <stdio.h>
#include <stdlib.h>
#include <envz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *envz_entry_wrapper(const char *envz, size_t envz_len, const char *name)
{
    typedef bool (*policy_fn_t)(const char *envz, size_t envz_len, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "envz_entry_policy");
    if (policy && !policy(envz, envz_len, name))
        abort();
    return envz_entry(envz, envz_len, name);
}

#include <envz.h>
#include <stdio.h>
#include <stdlib.h>
#include <envz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *envz_get_wrapper(const char *envz, size_t envz_len, const char *name)
{
    typedef bool (*policy_fn_t)(const char *envz, size_t envz_len, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "envz_get_policy");
    if (policy && !policy(envz, envz_len, name))
        abort();
    return envz_get(envz, envz_len, name);
}

#include <envz.h>
#include <stdio.h>
#include <stdlib.h>
#include <envz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

error_t envz_merge_wrapper(char **envz, size_t *envz_len, const char *envz2, size_t envz2_len, int override)
{
    typedef bool (*policy_fn_t)(char **envz, size_t *envz_len, const char *envz2, size_t envz2_len, int override);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "envz_merge_policy");
    if (policy && !policy(envz, envz_len, envz2, envz2_len, override))
        abort();
    return envz_merge(envz, envz_len, envz2, envz2_len, override);
}

#include <envz.h>
#include <stdio.h>
#include <stdlib.h>
#include <envz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void envz_remove_wrapper(char **envz, size_t *envz_len, const char *name)
{
    typedef bool (*policy_fn_t)(char **envz, size_t *envz_len, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "envz_remove_policy");
    if (policy && !policy(envz, envz_len, name))
        abort();
    envz_remove(envz, envz_len, name);
}

#include <envz.h>
#include <stdio.h>
#include <stdlib.h>
#include <envz.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void envz_strip_wrapper(char **envz, size_t *envz_len)
{
    typedef bool (*policy_fn_t)(char **envz, size_t *envz_len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "envz_strip_policy");
    if (policy && !policy(envz, envz_len))
        abort();
    envz_strip(envz, envz_len);
}

#include <sys/epoll.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int epoll_create_wrapper(int size)
{
    typedef bool (*policy_fn_t)(int size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "epoll_create_policy");
    if (policy && !policy(size))
        abort();
    return epoll_create(size);
}

#include <sys/epoll.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int epoll_create1_wrapper(int flags)
{
    typedef bool (*policy_fn_t)(int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "epoll_create1_policy");
    if (policy && !policy(flags))
        abort();
    return epoll_create1(flags);
}

#include <sys/epoll.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int epoll_ctl_wrapper(int epfd, int op, int fd, struct epoll_event *event)
{
    //wakka printffrom epoll_ctl\n");
    typedef bool (*policy_fn_t)(int epfd, int op, int fd, struct epoll_event *event);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "epoll_ctl_policy");
    if (policy && !policy(epfd, op, fd, event))
        abort();
    return epoll_ctl(epfd, op, fd, event);
}

#include <sys/epoll.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int epoll_pwait_wrapper(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask)
{
    typedef bool (*policy_fn_t)(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "epoll_pwait_policy");
    if (policy && !policy(epfd, events, maxevents, timeout, sigmask))
        abort();
    return epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

#include <sys/epoll.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int epoll_wait_wrapper(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    typedef bool (*policy_fn_t)(int epfd, struct epoll_event *events, int maxevents, int timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "epoll_wait_policy");
    if (policy && !policy(epfd, events, maxevents, timeout))
        abort();
    return epoll_wait(epfd, events, maxevents, timeout);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double erand48_wrapper(unsigned short xsubi[3])
{
    typedef bool (*policy_fn_t)(unsigned short xsubi[3]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "erand48_policy");

    if (policy && !policy(xsubi))
        abort();

    return erand48(xsubi);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

#include <stdlib.h>

int erand48_r_wrapper(unsigned short xsubi[3],
                      struct drand48_data *buffer,
                      double *result)
{
    typedef bool (*policy_fn_t)(unsigned short xsubi[3],
                                struct drand48_data *buffer,
                                double *result);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "erand48_r_policy");

    if (policy && !policy(xsubi, buffer, result))
        abort();

    return erand48_r(xsubi, buffer, result);
}


#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void err_wrapper(int eval, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    typedef bool (*policy_fn_t)(int, const char *fmt);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "err_policy");

    if (policy && !policy(eval, fmt))
    {
        va_end(args);
        abort();
    }

    verr(eval, fmt, args); // calls the real err()
    va_end(args);
}

#include <error.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <dlfcn.h>

void error_wrapper(int status, int errnum, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // build message from format + args
    char *msg = NULL;
    vasprintf(&msg, format, args);

    // collect args for policy (if you really want to record string args separately)
    const char *var_argv[64];
    int vi = 0;
    const char *next;
    va_list tmp;
    va_copy(tmp, args);
    while (vi < 63 && (next = va_arg(tmp, const char *)) != NULL)
    {
        var_argv[vi++] = next;
    }
    var_argv[vi] = NULL;
    va_end(tmp);

    typedef bool (*policy_fn_t)(int, int, const char *[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "error_policy");
    if (policy && !policy(status, errnum, var_argv))
    {
        free(msg);
        va_end(args);
        abort();
    }

    // call real error()
    error(status, errnum, "%s", msg);

    free(msg);
    va_end(args);
}

#include <error.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void error_at_line_wrapper(int status, int errnum, const char *filename, unsigned int linenum, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // Build message string
    char *msg = NULL;
    vasprintf(&msg, format, args);

    // Collect string arguments for policy
    const char *var_argv[64];
    int vi = 0;
    va_list tmp;
    va_copy(tmp, args);
    const char *next;
    while (vi < 63 && (next = va_arg(tmp, const char *)) != NULL)
    {
        var_argv[vi++] = next;
    }
    var_argv[vi] = NULL;
    va_end(tmp);

    // Policy function typedef: only types, no variable names
    typedef bool (*policy_fn_t)(int, int, const char *, unsigned int, const char *[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "error_at_line_policy");
    if (policy && !policy(status, errnum, filename, linenum, var_argv))
    {
        free(msg);
        va_end(args);
        abort();
    }

    // Call real error_at_line safely
    error_at_line(status, errnum, filename, linenum, "%s", msg);

    free(msg);
    va_end(args);
}

#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void errx_wrapper(int eval, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    // Collect string arguments for policy check
    const char *var_argv[64];
    int vi = 0;
    va_list tmp;
    va_copy(tmp, args);
    const char *next;
    while (vi < 63 && (next = va_arg(tmp, const char *)) != NULL)
    {
        var_argv[vi++] = next;
    }
    var_argv[vi] = NULL;
    va_end(tmp);

    // Policy function typedef: only types, no variable names
    typedef bool (*policy_fn_t)(int, const char *[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "errx_policy");
    if (policy && !policy(eval, var_argv))
    {
        va_end(args);
        abort();
    }

    // Call the real errx function
    verrx(eval, fmt, args); // note: verrx is declared in <err.h>

    va_end(args);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct ether_addr *ether_aton_wrapper(const char *c)
{
    typedef bool (*policy_fn_t)(const char *c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_aton_policy");
    if (policy && !policy(c))
        abort();
    return ether_aton(c);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct ether_addr *ether_aton_r_wrapper(const char *c, struct ether_addr *addr)
{
    typedef bool (*policy_fn_t)(const char *c, struct ether_addr *addr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_aton_r_policy");
    if (policy && !policy(c, addr))
        abort();
    return ether_aton_r(c, addr);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ether_hostton_wrapper(const char *hostname, struct ether_addr *addr)
{
    typedef bool (*policy_fn_t)(const char *hostname, struct ether_addr *addr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_hostton_policy");
    if (policy && !policy(hostname, addr))
        abort();
    return ether_hostton(hostname, addr);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ether_line_wrapper(const char *line, struct ether_addr *addr, char *hostname)
{
    typedef bool (*policy_fn_t)(const char *line, struct ether_addr *addr, char *hostname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_line_policy");
    if (policy && !policy(line, addr, hostname))
        abort();
    return ether_line(line, addr, hostname);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ether_ntoa_wrapper(const struct ether_addr *addr)
{
    typedef bool (*policy_fn_t)(const struct ether_addr *addr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_ntoa_policy");
    if (policy && !policy(addr))
        abort();
    return ether_ntoa(addr);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ether_ntoa_r_wrapper(const struct ether_addr *addr, char *buf)
{
    typedef bool (*policy_fn_t)(const struct ether_addr *addr, char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_ntoa_r_policy");
    if (policy && !policy(addr, buf))
        abort();
    return ether_ntoa_r(addr, buf);
}

#include <netinet/ether.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ether_ntohost_wrapper(char *hostname, const struct ether_addr *addr)
{
    typedef bool (*policy_fn_t)(char *hostname, const struct ether_addr *addr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ether_ntohost_policy");
    if (policy && !policy(hostname, addr))
        abort();
    return ether_ntohost(hostname, addr);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int euidaccess_wrapper(const char *pathname, int mode)
{
    typedef bool (*policy_fn_t)(const char *pathname, int mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "euidaccess_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return euidaccess(pathname, mode);
}

#include <sys/eventfd.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int eventfd_wrapper(unsigned int initval, int flags)
{
    typedef bool (*policy_fn_t)(unsigned int initval, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "eventfd_policy");
    if (policy && !policy(initval, flags))
        abort();
    return eventfd(initval, flags);
}

#include <sys/eventfd.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int eventfd_read_wrapper(int fd, eventfd_t *value)
{
    typedef bool (*policy_fn_t)(int fd, eventfd_t *value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "eventfd_read_policy");
    if (policy && !policy(fd, value))
        abort();
    return eventfd_read(fd, value);
}

#include <sys/eventfd.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int eventfd_write_wrapper(int fd, eventfd_t value)
{
    typedef bool (*policy_fn_t)(int fd, eventfd_t value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "eventfd_write_policy");
    if (policy && !policy(fd, value))
        abort();
    return eventfd_write(fd, value);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execl_wrapper(const char *pathname, const char *arg, ...)
{
    //wakka printffrom execl\n");
    va_list args;
    va_start(args, arg);
    char *argv[64];
    int i = 0;
    argv[i++] = (char *)arg;
    const char *next;
    while (i < 63 && (next = va_arg(args, const char *)) != NULL)
        argv[i++] = (char *)next;
    argv[i] = NULL;

    typedef bool (*policy_fn_t)(const char *pathname, char *argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execl_policy");
    if (policy && !policy(pathname, argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return execv(pathname, argv);
}

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execle_wrapper(const char *pathname, const char *arg, ...)
{
    va_list args;
    va_start(args, arg);

    char *argv[64];
    int i = 0;
    argv[i++] = (char *)arg;

    const char *next;
    while (i < 63 && (next = va_arg(args, const char *)) != NULL)
        argv[i++] = (char *)next;
    argv[i] = NULL;

    typedef bool (*policy_fn_t)(const char *pathname, char *argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execle_policy");
    if (policy && !policy(pathname, argv))
    {
        va_end(args);
        abort();
    }

    // envp is the last argument in execle, extract it from va_list
    char *const *envp = va_arg(args, char *const *);
    va_end(args);

    return execve(pathname, argv, envp);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execlp_wrapper(const char *file, const char *arg, ...)
{
    va_list args;
    va_start(args, arg);
    char *argv[64];
    int i = 0;
    argv[i++] = (char *)arg;
    const char *next;
    while (i < 63 && (next = va_arg(args, const char *)) != NULL)
        argv[i++] = (char *)next;
    argv[i] = NULL;

    typedef bool (*policy_fn_t)(const char *pathname, char *argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execlp_policy");
    if (policy && !policy(file, argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return execv(file, argv);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execv_wrapper(const char *pathname, char *const argv[])
{
    //wakka printffrom execv\n");
    typedef bool (*policy_fn_t)(const char *pathname, char *const argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execv_policy");
    if (policy && !policy(pathname, argv))
        abort();
    return execv(pathname, argv);
}

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execve_wrapper(const char *pathname, char *const argv[], char *const envp[])
{
    typedef bool (*policy_fn_t)(const char *pathname, char *const argv[], char *const envp[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execve_policy");
    if (policy && !policy(pathname, argv, envp))
        abort();
    return execve(pathname, argv, envp);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execveat_wrapper(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execveat_policy");
    if (policy && !policy(dirfd, pathname, argv, envp, flags))
        abort();
    return execveat(dirfd, pathname, argv, envp, flags);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execvp_wrapper(const char *file, char *const argv[])
{
    //wakka printffrom execvp\n");
    typedef bool (*policy_fn_t)(const char *file, char *const argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execvp_policy");
    if (policy && !policy(file, argv))
        abort();
    return execvp(file, argv);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int execvpe_wrapper(const char *file, char *const argv[], char *const envp[])
{
    typedef bool (*policy_fn_t)(const char *file, char *const argv[], char *const envp[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "execvpe_policy");
    if (policy && !policy(file, argv, envp))
        abort();
    return execvpe(file, argv, envp);
}

#include <strings.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void explicit_bzero_wrapper(void *s, size_t n)
{
    typedef bool (*policy_fn_t)(void *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "explicit_bzero_policy");
    if (policy && !policy(s, n))
        abort();
    explicit_bzero(s, n);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int faccessat_wrapper(int dirfd, const char *pathname, int mode, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, int mode, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "faccessat_policy");
    if (policy && !policy(dirfd, pathname, mode, flags))
        abort();
    return faccessat(dirfd, pathname, mode, flags);
}

#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fallocate_wrapper(int fd, int mode, off_t offset, off_t len)
{
    typedef bool (*policy_fn_t)(int fd, int mode, off_t offset, off_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fallocate_policy");
    if (policy && !policy(fd, mode, offset, len))
        abort();
    return fallocate(fd, mode, offset, len);
}

#include <fcntl.h>
#include <sys/fanotify.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fanotify_init_wrapper(unsigned int flags, unsigned int event_f_flags)
{
    typedef bool (*policy_fn_t)(unsigned int flags, unsigned int event_f_flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fanotify_init_policy");
    if (policy && !policy(flags, event_f_flags))
        abort();
    return fanotify_init(flags, event_f_flags);
}

#include <sys/fanotify.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fanotify_mark_wrapper(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname)
{
    typedef bool (*policy_fn_t)(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fanotify_mark_policy");
    if (policy && !policy(fanotify_fd, flags, mask, dirfd, pathname))
        abort();
    return fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fchdir_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fchdir_policy");
    if (policy && !policy(fd))
        abort();
    return fchdir(fd);
}

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fchmod_wrapper(int fd, mode_t mode)
{
    //wakka printffrom fchmod\n");
    typedef bool (*policy_fn_t)(int fd, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fchmod_policy");
    if (policy && !policy(fd, mode))
        abort();
    return fchmod(fd, mode);
}

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fchmodat_wrapper(int dirfd, const char *pathname, mode_t mode, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, mode_t mode, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fchmodat_policy");
    if (policy && !policy(dirfd, pathname, mode, flags))
        abort();
    return fchmodat(dirfd, pathname, mode, flags);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fchown_wrapper(int fd, uid_t owner, gid_t group)
{
    typedef bool (*policy_fn_t)(int fd, uid_t owner, gid_t group);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fchown_policy");
    if (policy && !policy(fd, owner, group))
        abort();
    return fchown(fd, owner, group);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fchownat_wrapper(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fchownat_policy");
    if (policy && !policy(dirfd, pathname, owner, group, flags))
        abort();
    return fchownat(dirfd, pathname, owner, group, flags);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fclose_wrapper(FILE *stream)
{
    FILE *out = fopen("fclose.txt", "a"); // create or overwrite
    if (!out)
    {
        perror("fopen");
        return 0;
    }

    int fd = fileno(stream);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len != -1)
    {
        buf[len] = '\0';
        fprintf(out, "from fclose: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
    }
    else
    {
        fprintf(out, "from fclose: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
    }

    fclose(out);

    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fclose_policy");
    if (policy && !policy(stream))
        abort();
    return fclose(stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fcloseall_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fcloseall_policy");
    if (policy && !policy())
        abort();
    return fcloseall();
}

#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fcntl_wrapper(int fd, int cmd, ...)
{
    FILE *log = fopen("fcntl.txt", "a");
    if (log != NULL)
    {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

        char buf[PATH_MAX];
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);

        if (len != -1)
        {
            buf[len] = '\0';
            fprintf(log, "from fcntl: cmd=%d, fd=%d, path=%s\n", cmd, fd, buf);
        }
        else
        {
            fprintf(log, "from fcntl: cmd=%d, fd=%d, path=%s\n", cmd, fd, path);
        }

        fclose(log);
    }

    va_list args;
    va_start(args, cmd);
    long var_argv[1];
    var_argv[0] = va_arg(args, long);

    typedef bool (*policy_fn_t)(int, long[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fcntl_policy");
    if (policy && !policy(fd, var_argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return fcntl(fd, var_argv[0]);
}

#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fcntl64_wrapper(int fd, int cmd, ...)
{
    //wakka printffrom fcntl64\n");
    va_list args;
    va_start(args, cmd);
    long var_argv[1];
    var_argv[0] = va_arg(args, long);

    typedef bool (*policy_fn_t)(int, long[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fcntl64_policy");
    if (policy && !policy(fd, var_argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return fcntl64(fd, var_argv[0]);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *fcvt_wrapper(double number, int ndigits, int *decpt, int *sign)
{
    typedef bool (*policy_fn_t)(double number, int ndigits, int *decpt, int *sign);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fcvt_policy");
    if (policy && !policy(number, ndigits, decpt, sign))
        abort();
    return fcvt(number, ndigits, decpt, sign);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fcvt_r_wrapper(double number, int ndigits, int *decpt, int *sign, char *buf, size_t len)
{
    typedef bool (*policy_fn_t)(double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fcvt_r_policy");
    if (policy && !policy(number, ndigits, decpt, sign, buf, len))
        abort();
    return fcvt_r(number, ndigits, decpt, sign, buf, len);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fdatasync_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fdatasync_policy");
    if (policy && !policy(fd))
        abort();
    return fdatasync(fd);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *fdopen_wrapper(int fd, const char *mode)
{
    //wakka printffrom fdopen\n");
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len != -1)
    {
        buf[len] = '\0';
        //wakka printffrom fdopen: mode=%s, fd=%d, path=%s\n", mode, fd, path);
    }
    else
    {
        //wakka printffrom fdopen: mode=%s, fd=%d, path=%s\n", mode, fd, path);
    }
    typedef bool (*policy_fn_t)(int fd, const char *mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fdopen_policy");
    if (policy && !policy(fd, mode))
        abort();
    return fdopen(fd, mode);
}

#include <sys/types.h>
#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

DIR *fdopendir_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fdopendir_policy");
    if (policy && !policy(fd))
        abort();
    return fdopendir(fd);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int feof_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "feof_policy");
    if (policy && !policy(stream))
        abort();
    return feof(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int feof_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "feof_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return feof_unlocked(stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ferror_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ferror_policy");
    if (policy && !policy(stream))
        abort();
    return ferror(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ferror_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ferror_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return ferror_unlocked(stream);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fexecve_wrapper(int fd, char *const argv[], char *const envp[])
{
    typedef bool (*policy_fn_t)(int fd, char *const argv[], char *const envp[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fexecve_policy");
    if (policy && !policy(fd, argv, envp))
        abort();
    return fexecve(fd, argv, envp);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fflush_wrapper(FILE *stream)
{
    FILE *out = fopen("fflush.txt", "a"); // create or overwrite
    if (!out)
    {
        perror("fopen");
        return 0;
    }

    fprintf(out, "from fflush\n");

    if (stream != NULL)
    {
        int fd = fileno(stream); // get the fd from FILE*
        if (fd != -1)
        {
            fprintf(out, "fd: %d\n", fd);
        }
        else
        {
            fprintf(out, "fd: <invalid>\n");
        }
    }
    else
    {
        fprintf(out, "fflush(NULL) called (all open streams)\n");
    }

    fclose(out);

    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fflush_policy");
    if (policy && !policy(stream))
        abort();
    return fflush(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fflush_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fflush_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return fflush_unlocked(stream);
}

#include <strings.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ffs_wrapper(int i)
{
    typedef bool (*policy_fn_t)(int i);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ffs_policy");
    if (policy && !policy(i))
        abort();
    return ffs(i);
}

#include <strings.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ffsl_wrapper(long i)
{
    typedef bool (*policy_fn_t)(long i);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ffsl_policy");
    if (policy && !policy(i))
        abort();
    return ffsl(i);
}

#include <strings.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ffsll_wrapper(long long i)
{
    typedef bool (*policy_fn_t)(long long i);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ffsll_policy");
    if (policy && !policy(i))
        abort();
    return ffsll(i);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fgetc_wrapper(FILE *stream)
{
    FILE *logf = fopen("fgetc.txt", "a");
    if (logf)
    {
        fprintf(logf, "From fgetc\n");
        int fd = fileno(stream);
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

        char buf[PATH_MAX];
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len != -1)
        {
            buf[len] = '\0';
            fprintf(logf, "from fgetc: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
        }
        else
        {
            fprintf(logf, "from fgetc: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
        }
        fclose(logf);
    }

    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetc_policy");
    if (policy && !policy(stream))
        abort();
    return fgetc(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fgetc_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetc_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return fgetc_unlocked(stream);
}

#include <stdio.h>
#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct group *fgetgrent_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetgrent_policy");
    if (policy && !policy(stream))
        abort();
    return fgetgrent(stream);
}

#include <grp.h>
#include <grp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fgetgrent_r_wrapper(FILE *stream, struct group *gbuf, char *buf, size_t buflen, struct group **gbufp)
{
    typedef bool (*policy_fn_t)(FILE *stream, struct group *gbuf, char *buf, size_t buflen, struct group **gbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetgrent_r_policy");
    if (policy && !policy(stream, gbuf, buf, buflen, gbufp))
        abort();
    return fgetgrent_r(stream, gbuf, buf, buflen, gbufp);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fgetpos_wrapper(FILE *stream, fpos_t *pos)
{
    typedef bool (*policy_fn_t)(FILE *stream, fpos_t *pos);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetpos_policy");
    if (policy && !policy(stream, pos))
        abort();
    return fgetpos(stream, pos);
}

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct passwd *fgetpwent_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetpwent_policy");
    if (policy && !policy(stream))
        abort();
    return fgetpwent(stream);
}

#include <pwd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fgetpwent_r_wrapper(FILE *stream, struct passwd *pwbuf, char *buf, size_t buflen, struct passwd **pwbufp)
{
    typedef bool (*policy_fn_t)(FILE *stream, struct passwd *pwbuf, char *buf, size_t buflen, struct passwd **pwbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetpwent_r_policy");
    if (policy && !policy(stream, pwbuf, buf, buflen, pwbufp))
        abort();
    return fgetpwent_r(stream, pwbuf, buf, buflen, pwbufp);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *fgets_wrapper(char *s, int size, FILE *stream)
{
    //wakka printffrom fgets\n");
    typedef bool (*policy_fn_t)(char *s, int size, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgets_policy");
    if (policy && !policy(s, size, stream))
        abort();
    return fgets(s, size, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *fgets_unlocked_wrapper(char *s, int n, FILE *stream)
{
    typedef bool (*policy_fn_t)(char *s, int n, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgets_unlocked_policy");
    if (policy && !policy(s, n, stream))
        abort();
    return fgets_unlocked(s, n, stream);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct spwd *fgetspent_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetspent_policy");
    if (policy && !policy(stream))
        abort();
    return fgetspent(stream);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fgetspent_r_wrapper(FILE *stream, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp)
{
    typedef bool (*policy_fn_t)(FILE *stream, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetspent_r_policy");
    if (policy && !policy(stream, spbuf, buf, buflen, spbufp))
        abort();
    return fgetspent_r(stream, spbuf, buf, buflen, spbufp);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t fgetwc_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetwc_policy");
    if (policy && !policy(stream))
        abort();
    return fgetwc(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t fgetwc_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetwc_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return fgetwc_unlocked(stream);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *fgetws_wrapper(wchar_t *ws, int n, FILE *stream)
{
    typedef bool (*policy_fn_t)(wchar_t *ws, int n, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetws_policy");
    if (policy && !policy(ws, n, stream))
        abort();
    return fgetws(ws, n, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *fgetws_unlocked_wrapper(wchar_t *ws, int n, FILE *stream)
{
    typedef bool (*policy_fn_t)(wchar_t *ws, int n, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetws_unlocked_policy");
    if (policy && !policy(ws, n, stream))
        abort();
    return fgetws_unlocked(ws, n, stream);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t fgetxattr_wrapper(int fd, const char *name, void *value, size_t size)
{
    typedef bool (*policy_fn_t)(int fd, const char *name, void *value, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fgetxattr_policy");
    if (policy && !policy(fd, name, value, size))
        abort();
    return fgetxattr(fd, name, value, size);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fileno_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fileno_policy");
    if (policy && !policy(stream))
        abort();
    return fileno(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fileno_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fileno_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return fileno_unlocked(stream);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int finite_wrapper(double x)
{
    typedef bool (*policy_fn_t)(double x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "finite_policy");
    if (policy && !policy(x))
        abort();
    return finite(x);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int finitef_wrapper(float x)
{
    typedef bool (*policy_fn_t)(float x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "finitef_policy");
    if (policy && !policy(x))
        abort();
    return finitef(x);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int finitel_wrapper(long double x)
{
    typedef bool (*policy_fn_t)(long double x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "finitel_policy");
    if (policy && !policy(x))
        abort();
    return finitel(x);
}

#include <sys/types.h>
#include <sys/xattr.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t flistxattr_wrapper(int fd, char *list, size_t size)
{
    typedef bool (*policy_fn_t)(int fd, char *list, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "flistxattr_policy");
    if (policy && !policy(fd, list, size))
        abort();
    return flistxattr(fd, list, size);
}

#include <sys/file.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int flock_wrapper(int fd, int operation)
{
    //wakka printffrom flock\n");
    typedef bool (*policy_fn_t)(int fd, int operation);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "flock_policy");
    if (policy && !policy(fd, operation))
        abort();
    return flock(fd, operation);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void flockfile_wrapper(FILE *filehandle)
{
    typedef bool (*policy_fn_t)(FILE *filehandle);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "flockfile_policy");
    if (policy && !policy(filehandle))
        abort();
    flockfile(filehandle);
}

#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *fmemopen_wrapper(void *buf, size_t size, const char *mode)
{
    typedef bool (*policy_fn_t)(void *buf, size_t size, const char *mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fmemopen_policy");
    if (policy && !policy(buf, size, mode))
        abort();
    return fmemopen(buf, size, mode);
}

#include <fmtmsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <fmtmsg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fmtmsg_wrapper(long clsification, const char *label, int severity, const char *text, const char *action, const char *tag)
{
    typedef bool (*policy_fn_t)(long clsification, const char *label, int severity, const char *text, const char *action, const char *tag);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fmtmsg_policy");
    if (policy && !policy(clsification, label, severity, text, action, tag))
        abort();
    return fmtmsg(clsification, label, severity, text, action, tag);
}

#include <fnmatch.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fnmatch_wrapper(const char *pattern, const char *string, int flags)
{
    typedef bool (*policy_fn_t)(const char *pattern, const char *string, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fnmatch_policy");
    if (policy && !policy(pattern, string, flags))
        abort();
    return fnmatch(pattern, string, flags);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *fopen_wrapper(const char *pathname, const char *mode)
{
    FILE *out = fopen("fopen.txt", "a"); // create or overwrite
    if (!out)
    {
        perror("fopen");
        return NULL;
    }

    fprintf(out, "from fopen\n");
    fprintf(out, "name : %s\n", pathname);
    fprintf(out, "mode : %s\n", mode);

    fclose(out);

    typedef bool (*policy_fn_t)(const char *pathname, const char *mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fopen_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return fopen(pathname, mode);
}


#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *fopen64_wrapper(const char *pathname, const char *mode)
{
    FILE *out = fopen("fopen64.txt", "a"); // create or overwrite
    if (!out)
    {
        perror("fopen");
        return NULL;
    }

    fprintf(out, "from fopen64\n");
    fprintf(out, "name : %s\n", pathname);
    fprintf(out, "mode : %s\n", mode);

    fclose(out);

    typedef bool (*policy_fn_t)(const char *pathname, const char *mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fopen_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return fopen64(pathname, mode);
}

#include <stdio.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *fopencookie_wrapper(void *cookie, const char *mode, cookie_io_functions_t io_funcs)
{
    typedef bool (*policy_fn_t)(void *cookie, const char *mode, cookie_io_functions_t io_funcs);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fopencookie_policy");
    if (policy && !policy(cookie, mode, io_funcs))
        abort();
    return fopencookie(cookie, mode, io_funcs);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t fork_wrapper(void)
{
    //wakka printfhello from fork\n");
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fork_policy");
    if (policy && !policy())
        abort();
    return fork();
}

#include <pty.h>
#include <utmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t forkpty_wrapper(int *amaster, char *name, const struct termios *termp, const struct winsize *winp)
{
    typedef bool (*policy_fn_t)(int *amaster, char *name, const struct termios *termp, const struct winsize *winp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "forkpty_policy");
    if (policy && !policy(amaster, name, termp, winp))
        abort();
    return forkpty(amaster, name, termp, winp);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long fpathconf_wrapper(int fd, int name)
{
    typedef bool (*policy_fn_t)(int fd, int name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fpathconf_policy");
    if (policy && !policy(fd, name))
        abort();
    return fpathconf(fd, name);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fprintf_wrapper(FILE *stream, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    // --- Logging functionality added here ---
    FILE *log_fp = fopen("/tmp/fprintf_wrapper.log", "w");
    if (log_fp)
    {
        fprintf(log_fp, "[fprintf_wrapper] Called with format: %s\n", format);
        for (int i = 0; i < vi; i++)
        {
            fprintf(log_fp, "  arg[%d]: %s\n", i, var_argv[i] ? var_argv[i] : "(null)");
        }
        fclose(log_fp);
    }
    // ----------------------------------------

    typedef bool (*policy_fn_t)(FILE *, const char *[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fprintf_policy");
    if (policy && !policy(stream, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <bits/stdio2.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>

int __fprintf_chk_wrapper(FILE *stream, int flag, const char *format, ...)
{
    va_list args, args_copy;
    va_start(args, format);
    va_copy(args_copy, args);

    const void *var_argv[64];
    int vi = 0;
    const void *next;
    while (vi < 63 && (next = va_arg(args, void *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(FILE *, int, const void *[]);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "fprintf_policy");
    if (policy && !policy(stream, flag, var_argv))
        abort();

    // Fallback: __vfprintf_chk not available -> use vfprintf
    int ret = vfprintf(stream, format, args_copy);

    va_end(args_copy);
    va_end(args);
    return ret;
}


#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fputc_wrapper(int c, FILE *stream)
{
    FILE *logf = fopen("fputc.txt", "a");
    if (logf)
    {
        fprintf(logf, "from fputc\n");
        int fd = fileno(stream);
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

        char buf[PATH_MAX];
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len != -1)
        {
            buf[len] = '\0';
            fprintf(logf, "from fputc: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
        }
        else
        {
            fprintf(logf, "from fputc: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
        }
        fclose(logf);
    }

    typedef bool (*policy_fn_t)(int c, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputc_policy");
    if (policy && !policy(c, stream))
        abort();
    return fputc(c, stream);
}

int __sprintf_chk(char *s, int flag, size_t slen, const char *fmt, ...)
{
    //wakka printfsprintf bhai");
    typedef bool (*policy_fn_t)(char *s, int flag, size_t slen, const char *fmt, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__sprintf_chk_policy");

    va_list ap;
    va_start(ap, fmt);

    if (policy)
    {
        va_list ap_copy;
        va_copy(ap_copy, ap);
        if (!policy(s, flag, slen, fmt, ap_copy))
        {
            va_end(ap_copy);
            va_end(ap);
            abort();
        }
        va_end(ap_copy);
    }

    // direct call to libc's __vsprintf_chk (no dlsym)
    int ret = __vsprintf_chk(s, flag, slen, fmt, ap);
    va_end(ap);
    return ret;
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fputc_unlocked_wrapper(int c, FILE *stream)
{
    typedef bool (*policy_fn_t)(int c, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputc_unlocked_policy");
    if (policy && !policy(c, stream))
        abort();
    return fputc_unlocked(c, stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fputs_wrapper(const char *s, FILE *stream)
{
    //wakka printffrom puts\n");
    typedef bool (*policy_fn_t)(const char *s, FILE *stream);

    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputs_policy");
    if (policy && !policy(s, stream))
        abort();
    return fputs(s, stream);
}

#include <pthread.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

extern "C"
int pthread_mutex_lock_wrapper(pthread_mutex_t *mutex)
{
    //wakka printf[WRAP] pthread_mutex_lock\n");

    typedef bool (*policy_fn_t)(pthread_mutex_t *mutex);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutex_lock_policy");

    if (policy && !policy(mutex))
        abort();

    typedef int (*real_fn_t)(pthread_mutex_t *);
    static real_fn_t real = nullptr;
    if (!real) real = (real_fn_t)dlsym(RTLD_NEXT, "pthread_mutex_lock");
    return real(mutex);
}


extern "C"
int pthread_mutex_unlock_wrapper(pthread_mutex_t *mutex)
{
    //wakka printf[WRAP] pthread_mutex_unlock\n");

    typedef bool (*policy_fn_t)(pthread_mutex_t *mutex);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutex_unlock_policy");

    if (policy && !policy(mutex))
        abort();

    typedef int (*real_fn_t)(pthread_mutex_t *);
    static real_fn_t real = nullptr;
    if (!real) real = (real_fn_t)dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    return real(mutex);
}



extern "C"
int pthread_rwlock_rdlock_wrapper(pthread_rwlock_t *rwlock)
{
    //wakka printf[WRAP] pthread_rwlock_rdlock\n");

    typedef bool (*policy_fn_t)(pthread_rwlock_t *rwlock);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_rwlock_rdlock_policy");

    if (policy && !policy(rwlock))
        abort();

    typedef int (*real_fn_t)(pthread_rwlock_t *);
    static real_fn_t real = nullptr;
    if (!real) real = (real_fn_t)dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");
    return real(rwlock);
}


extern "C"
int pthread_rwlock_unlock_wrapper(pthread_rwlock_t *rwlock)
{
    //wakka printf[WRAP] pthread_rwlock_unlock\n");

    typedef bool (*policy_fn_t)(pthread_rwlock_t *rwlock);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_rwlock_unlock_policy");

    if (policy && !policy(rwlock))
        abort();

    typedef int (*real_fn_t)(pthread_rwlock_t *);
    static real_fn_t real = nullptr;
    if (!real) real = (real_fn_t)dlsym(RTLD_NEXT, "pthread_rwlock_unlock");
    return real(rwlock);
}




#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fputs_unlocked_wrapper(const char *s, FILE *stream)
{
    typedef bool (*policy_fn_t)(const char *s, FILE *stream);

    FILE *logf = fopen("/tmp/fputs_log.txt", "w");
    if (logf)
    {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        fprintf(logf, "[%02d:%02d:%02d] fputs(s=\"%s\", stream=%p)\n",
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                s ? s : "(null)", (void *)stream);
        fclose(logf); // close immediately
    }

    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputs_unlocked_policy");
    if (policy && !policy(s, stream))
        abort();
    return fputs_unlocked(s, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t fputwc_wrapper(wchar_t wc, FILE *stream)
{
    typedef bool (*policy_fn_t)(wchar_t wc, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputwc_policy");
    if (policy && !policy(wc, stream))
        abort();
    return fputwc(wc, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t fputwc_unlocked_wrapper(wchar_t wc, FILE *stream)
{
    typedef bool (*policy_fn_t)(wchar_t wc, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputwc_unlocked_policy");
    if (policy && !policy(wc, stream))
        abort();
    return fputwc_unlocked(wc, stream);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fputws_wrapper(const wchar_t *ws, FILE *stream)
{
    typedef bool (*policy_fn_t)(const wchar_t *ws, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputws_policy");
    if (policy && !policy(ws, stream))
        abort();
    return fputws(ws, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fputws_unlocked_wrapper(const wchar_t *ws, FILE *stream)
{
    typedef bool (*policy_fn_t)(const wchar_t *ws, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fputws_unlocked_policy");
    if (policy && !policy(ws, stream))
        abort();
    return fputws_unlocked(ws, stream);
}

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t fread_wrapper(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    FILE *out = fopen("fread.txt", "a"); // create or overwrite
    if (!out)
    {
        perror("fopen");
        return 0;
    }

    int fd = fileno(stream);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len != -1)
    {
        buf[len] = '\0';
        fprintf(out, "from fread: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
    }
    else
    {
        fprintf(out, "from fread: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
    }

    fclose(out);

    typedef bool (*policy_fn_t)(void *ptr, size_t size, size_t nmemb, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fread_policy");
    if (policy && !policy(ptr, size, nmemb, stream))
        abort();
    return fread(ptr, size, nmemb, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t fread_unlocked_wrapper(void *ptr, size_t size, size_t n, FILE *stream)
{
    typedef bool (*policy_fn_t)(void *ptr, size_t size, size_t n, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fread_unlocked_policy");
    if (policy && !policy(ptr, size, n, stream))
        abort();
    return fread_unlocked(ptr, size, n, stream);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void free_wrapper(void *ptr)
{
    typedef bool (*policy_fn_t)(void *ptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "free_policy");
    if (policy && !policy(ptr))
        abort();
    free(ptr);
}

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void freeaddrinfo_wrapper(struct addrinfo *res)
{
    typedef bool (*policy_fn_t)(struct addrinfo *res);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "freeaddrinfo_policy");
    if (policy && !policy(res))
        abort();
    freeaddrinfo(res);
}

#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void freeifaddrs_wrapper(struct ifaddrs *ifa)
{
    typedef bool (*policy_fn_t)(struct ifaddrs *ifa);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "freeifaddrs_policy");
    if (policy && !policy(ifa))
        abort();
    freeifaddrs(ifa);
}

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void freelocale_wrapper(locale_t locobj)
{
    typedef bool (*policy_fn_t)(locale_t locobj);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "freelocale_policy");
    if (policy && !policy(locobj))
        abort();
    freelocale(locobj);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fremovexattr_wrapper(int fd, const char *name)
{
    typedef bool (*policy_fn_t)(int fd, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fremovexattr_policy");
    if (policy && !policy(fd, name))
        abort();
    return fremovexattr(fd, name);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *freopen_wrapper(const char *pathname, const char *mode, FILE *stream)
{
    typedef bool (*policy_fn_t)(const char *pathname, const char *mode, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "freopen_policy");
    if (policy && !policy(pathname, mode, stream))
        abort();
    return freopen(pathname, mode, stream);
}

#include <math.h>
#include <math.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double frexp_wrapper(double x, int *exp)
{
    typedef bool (*policy_fn_t)(double x, int *exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "frexp_policy");
    if (policy && !policy(x, exp))
        abort();
    return frexp(x, exp);
}

#include <math.h>
#include <math.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

float frexpf_wrapper(float x, int *exp)
{
    typedef bool (*policy_fn_t)(float x, int *exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "frexpf_policy");
    if (policy && !policy(x, exp))
        abort();
    return frexpf(x, exp);
}

#include <math.h>
#include <math.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long double frexpl_wrapper(long double x, int *exp)
{
    typedef bool (*policy_fn_t)(long double x, int *exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "frexpl_policy");
    if (policy && !policy(x, exp))
        abort();
    return frexpl(x, exp);
}

#include <stdio.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fscanf_wrapper(FILE *stream, const char *format, ...)
{
    va_list args, args_copy;
    va_start(args, format);

    // Copy args so we can safely read them for the policy
    va_copy(args_copy, args);

    // Collect arguments into an array
    void *var_argv[64];
    int vi = 0;
    void *next;

    // WARNING: this assumes all args are pointers (int*, char*, etc.)
    while (vi < 63)
    {
        next = va_arg(args_copy, void *);
        if (!next)
            break; // stop if NULL
        var_argv[vi++] = next;
    }
    var_argv[vi] = NULL;

    // Typedef for policy function
    typedef bool (*policy_fn_t)(FILE *, void *[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fscanf_policy");

    if (policy && !policy(stream, var_argv))
    {
        va_end(args_copy);
        va_end(args);
        abort();
    }

    // Call the real vfscanf
    int ret = vfscanf(stream, format, args);

    va_end(args_copy);
    va_end(args);
    return ret;
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fseek_wrapper(FILE *stream, long offset, int whence)
{
    //wakka printffrom fseek\n");
    typedef bool (*policy_fn_t)(FILE *stream, long offset, int whence);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fseek_policy");
    if (policy && !policy(stream, offset, whence))
        abort();
    return fseek(stream, offset, whence);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fseeko_wrapper(FILE *stream, off_t offset, int whence)
{
    //wakka printffrom fseeko\n");
    typedef bool (*policy_fn_t)(FILE *stream, off_t offset, int whence);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fseeko_policy");
    if (policy && !policy(stream, offset, whence))
        abort();
    return fseeko(stream, offset, whence);
}

int fseeko64_wrapper(FILE *stream, off_t offset, int whence)
{
    FILE *logf = fopen("fseeko64.txt", "a");
    if (logf)
    {
        fprintf(logf, "From fseeko64\n");
        int fd = fileno(stream);
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

        char buf[PATH_MAX];
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len != -1)
        {
            buf[len] = '\0';
            fprintf(logf, "from fseeko64: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
        }
        else
        {
            fprintf(logf, "from fseeko64: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
        }
        fclose(logf);
    }

    typedef bool (*policy_fn_t)(FILE *stream, off_t offset, int whence);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fseeko_policy");
    if (policy && !policy(stream, offset, whence))
        abort();
    return fseeko64(stream, offset, whence);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fsetpos_wrapper(FILE *stream, const fpos_t *pos)
{
    typedef bool (*policy_fn_t)(FILE *stream, const fpos_t *pos);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fsetpos_policy");
    if (policy && !policy(stream, pos))
        abort();
    return fsetpos(stream, pos);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fsetxattr_wrapper(int fd, const char *name, const void *value, size_t size, int flags)
{
    typedef bool (*policy_fn_t)(int fd, const char *name, const void *value, size_t size, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fsetxattr_policy");
    if (policy && !policy(fd, name, value, size, flags))
        abort();
    return fsetxattr(fd, name, value, size, flags);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstat_wrapper(int fd, struct stat *statbuf)
{
    typedef bool (*policy_fn_t)(int fd, struct stat *statbuf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fstat_policy");
    if (policy && !policy(fd, statbuf))
        abort();
    return fstat(fd, statbuf);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstat64_wrapper(int fd, struct stat64 *buf)
{
    typedef bool (*policy_fn_t)(int fd, struct stat64 *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fstat64_policy");
    if (policy && !policy(fd, buf))
        abort();
    return fstat64(fd, buf);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstatat_wrapper(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fstatat_policy");
    if (policy && !policy(dirfd, pathname, statbuf, flags))
        abort();
    return fstatat(dirfd, pathname, statbuf, flags);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstatat64_wrapper(int dirfd, const char *pathname,
                      struct stat *statbuf, int flags)
{
    typedef bool (*policy_fn_t)(int, const char *, struct stat *, int);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "fstatat64_policy");
    if (policy && !policy(dirfd, pathname, statbuf, flags))
        abort();

    return fstatat(dirfd, pathname, statbuf, flags);   // <-- NOT 64
}

#include <sys/vfs.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstatfs_wrapper(int fd, struct statfs *buf)
{
    typedef bool (*policy_fn_t)(int fd, struct statfs *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fstatfs_policy");
    if (policy && !policy(fd, buf))
        abort();
    return fstatfs(fd, buf);
}

#include <sys/vfs.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstatfs64_wrapper(int fd, struct statfs *buf)
{
    typedef bool (*policy_fn_t)(int fd, struct statfs *buf);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "fstatfs64_policy");
    if (policy && !policy(fd, buf))
        abort();

    return fstatfs(fd, buf);   // <<== correct modern call
}

#include <sys/statvfs.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fstatvfs_wrapper(int fd, struct statvfs *buf)
{
    typedef bool (*policy_fn_t)(int fd, struct statvfs *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fstatvfs_policy");
    if (policy && !policy(fd, buf))
        abort();
    return fstatvfs(fd, buf);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fsync_wrapper(int fd)
{
    //wakka printffrom fsync\n");
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fsync_policy");
    if (policy && !policy(fd))
        abort();
    return fsync(fd);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long ftell_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftell_policy");
    if (policy && !policy(stream))
        abort();
    return ftell(stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

off_t ftello_wrapper(FILE *stream)
{
    //wakka printffrom ftello\n");
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftello_policy");
    if (policy && !policy(stream))
        abort();
    return ftello(stream);
}

off_t ftello64_wrapper(FILE *stream)
{
    FILE *logf = fopen("ftello64.txt", "a");
    if (logf)
    {
        fprintf(logf, "From ftello64\n");
        int fd = fileno(stream);
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

        char buf[PATH_MAX];
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len != -1)
        {
            buf[len] = '\0';
            fprintf(logf, "from ftello64: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
        }
        else
        {
            fprintf(logf, "from ftello64: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
        }
        fclose(logf);
    }

    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftello_policy");
    if (policy && !policy(stream))
        abort();
    return ftello(stream);
}

#include <sys/types.h>
#include <sys/ipc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

key_t ftok_wrapper(const char *pathname, int proj_id)
{
    typedef bool (*policy_fn_t)(const char *pathname, int proj_id);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftok_policy");
    if (policy && !policy(pathname, proj_id))
        abort();
    return ftok(pathname, proj_id);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ftruncate_wrapper(int fd, off_t length)
{
    //wakka printffrom ftruncate\n");
    typedef bool (*policy_fn_t)(int fd, off_t length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftruncate_policy");
    if (policy && !policy(fd, length))
        abort();
    return ftruncate(fd, length);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ftruncate64_wrapper(int fd, off_t length)
{
    typedef bool (*policy_fn_t)(int fd, off_t length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftruncate64_policy");
    if (policy && !policy(fd, length))
        abort();
    return ftruncate64(fd, length);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ftrylockfile_wrapper(FILE *filehandle)
{
    typedef bool (*policy_fn_t)(FILE *filehandle);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftrylockfile_policy");
    if (policy && !policy(filehandle))
        abort();
    return ftrylockfile(filehandle);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FTSENT *fts_children_wrapper(FTS *ftsp, int instr)
{
    typedef bool (*policy_fn_t)(FTS *ftsp, int instr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fts_children_policy");
    if (policy && !policy(ftsp, instr))
        abort();
    return fts_children(ftsp, instr);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fts_close_wrapper(FTS *ftsp)
{
    typedef bool (*policy_fn_t)(FTS *ftsp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fts_close_policy");
    if (policy && !policy(ftsp))
        abort();
    return fts_close(ftsp);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FTS *fts_open_wrapper(char *const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **))
{
    typedef bool (*policy_fn_t)(char *const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fts_open_policy");
    if (policy && !policy(path_argv, options, compar))
        abort();
    return fts_open(path_argv, options, compar);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FTSENT *fts_read_wrapper(FTS *ftsp)
{
    typedef bool (*policy_fn_t)(FTS *ftsp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fts_read_policy");
    if (policy && !policy(ftsp))
        abort();
    return fts_read(ftsp);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fts_set_wrapper(FTS *ftsp, FTSENT *f, int instr)
{
    typedef bool (*policy_fn_t)(FTS *ftsp, FTSENT *f, int instr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fts_set_policy");
    if (policy && !policy(ftsp, f, instr))
        abort();
    return fts_set(ftsp, f, instr);
}

#include <ftw.h>
#include <ftw.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ftw_wrapper(const char *dirpath, int (*fn)(const char *fpath, const struct stat *sb, int typeflag), int nopenfd)
{
    typedef bool (*policy_fn_t)(const char *dirpath, int (*fn)(const char *fpath, const struct stat *sb, int typeflag), int nopenfd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ftw_policy");
    if (policy && !policy(dirpath, fn, nopenfd))
        abort();
    return ftw(dirpath, fn, nopenfd);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void funlockfile_wrapper(FILE *filehandle)
{
    typedef bool (*policy_fn_t)(FILE *filehandle);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "funlockfile_policy");
    if (policy && !policy(filehandle))
        abort();
    funlockfile(filehandle);
}

#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int futimens_wrapper(int fd, const struct timespec times[2])
{
    typedef bool (*policy_fn_t)(int fd, const struct timespec times[2]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "futimens_policy");
    if (policy && !policy(fd, times))
        abort();
    return futimens(fd, times);
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int futimes_wrapper(int fd, const struct timeval tv[2])
{
    typedef bool (*policy_fn_t)(int fd, const struct timeval tv[2]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "futimes_policy");
    if (policy && !policy(fd, tv))
        abort();
    return futimes(fd, tv);
}

#include <fcntl.h>
#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int futimesat_wrapper(int dirfd, const char *pathname, const struct timeval times[2])
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, const struct timeval times[2]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "futimesat_policy");
    if (policy && !policy(dirfd, pathname, times))
        abort();
    return futimesat(dirfd, pathname, times);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fwide_wrapper(FILE *stream, int mode)
{
    typedef bool (*policy_fn_t)(FILE *stream, int mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fwide_policy");
    if (policy && !policy(stream, mode))
        abort();
    return fwide(stream, mode);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int fwprintf_wrapper(FILE *stream, const wchar_t *format, ...)
{
    va_list args, args_copy;
    va_start(args, format);
    va_copy(args_copy, args);

    void *var_argv[64];
    int vi = 0;
    void *next;

    // Collect all arguments into an array
    while (vi < 63)
    {
        next = va_arg(args_copy, void *);
        if (!next)
            break;
        var_argv[vi++] = next;
    }
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(FILE *, void *[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fwprintf_policy");

    if (policy && !policy(stream, var_argv))
    {
        va_end(args_copy);
        va_end(args);
        abort();
    }

    // Call the real vfwprintf
    int ret = vfwprintf(stream, format, args);

    va_end(args_copy);
    va_end(args);
    return ret;
}

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t fwrite_wrapper(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    // FILE *out = fopen("fwrite.txt", "a"); // create or overwrite
    // if (!out)
    // {
    //     perror("fopen");
    //     return 0;
    // }

    // int fd = fileno(stream);
    // char path[PATH_MAX];
    // snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    // char buf[PATH_MAX];
    // ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    // if (len != -1)
    // {
    //     buf[len] = '\0';
    //     fprintf(out, "from fwrite: FILE*=%p, fd=%d, path=%s\n", (void *)stream, fd, buf);
    // }
    // else
    // {
    //     fprintf(out, "from fwrite: FILE*=%p, fd=%d, path=unknown\n", (void *)stream, fd);
    // }

    // fclose(out);

    typedef bool (*policy_fn_t)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fwrite_policy");
    if (policy && !policy(ptr, size, nmemb, stream))
        abort();
    return fwrite(ptr, size, nmemb, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t fwrite_unlocked_wrapper(const void *ptr, size_t size, size_t n, FILE *stream)
{
    typedef bool (*policy_fn_t)(const void *ptr, size_t size, size_t n, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "fwrite_unlocked_policy");
    if (policy && !policy(ptr, size, n, stream))
        abort();
    return fwrite_unlocked(ptr, size, n, stream);
}

#include <netdb.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gai_cancel_wrapper(struct gaicb *req)
{
    typedef bool (*policy_fn_t)(struct gaicb *req);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gai_cancel_policy");
    if (policy && !policy(req))
        abort();
    return gai_cancel(req);
}

#include <netdb.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gai_error_wrapper(struct gaicb *req)
{
    typedef bool (*policy_fn_t)(struct gaicb *req);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gai_error_policy");
    if (policy && !policy(req))
        abort();
    return gai_error(req);
}

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *gai_strerror_wrapper(int errcode)
{
    typedef bool (*policy_fn_t)(int errcode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gai_strerror_policy");
    if (policy && !policy(errcode))
        abort();
    return gai_strerror(errcode);
}

#include <netdb.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gai_suspend_wrapper(const struct gaicb *const list[], int nitems, const struct timespec *timeout)
{
    typedef bool (*policy_fn_t)(const struct gaicb *const list[], int nitems, const struct timespec *timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gai_suspend_policy");
    if (policy && !policy(list, nitems, timeout))
        abort();
    return gai_suspend(list, nitems, timeout);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *gcvt_wrapper(double number, int ndigit, char *buf)
{
    typedef bool (*policy_fn_t)(double number, int ndigit, char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gcvt_policy");
    if (policy && !policy(number, ndigit, buf))
        abort();
    return gcvt(number, ndigit, buf);
}

#include <sys/sysinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long get_avphys_pages_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_avphys_pages_policy");
    if (policy && !policy())
        abort();
    return get_avphys_pages();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *get_current_dir_name_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_current_dir_name_policy");
    if (policy && !policy())
        abort();
    return get_current_dir_name();
}

// #include <linux/module.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int get_kernel_syms_wrapper(struct kernel_sym *table)
// {
//     typedef bool (*policy_fn_t)(struct kernel_sym *table);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_kernel_syms_policy");
//     if (policy && !policy(table))
//         abort();
//     return get_kernel_syms(table);
// }

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void get_myaddress_wrapper(struct sockaddr_in *addr)
// {
//     typedef bool (*policy_fn_t)(struct sockaddr_in *addr);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_myaddress_policy");
//     if (policy && !policy(addr))
//         abort();
//     get_myaddress(addr);
// }

#include <sys/sysinfo.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sysinfo.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int get_nprocs_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_nprocs_policy");
    if (policy && !policy())
        abort();
    return get_nprocs();
}

#include <sys/sysinfo.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sysinfo.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int get_nprocs_conf_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_nprocs_conf_policy");
    if (policy && !policy())
        abort();
    return get_nprocs_conf();
}

#include <sys/sysinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long get_phys_pages_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "get_phys_pages_policy");
    if (policy && !policy())
        abort();
    return get_phys_pages();
}

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getaddrinfo_wrapper(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    //wakka printffrom getaddrinfo\n");
    typedef bool (*policy_fn_t)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getaddrinfo_policy");
    if (policy && !policy(node, service, hints, res))
        abort();
    return getaddrinfo(node, service, hints, res);
}

#include <netdb.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getaddrinfo_a_wrapper(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
    typedef bool (*policy_fn_t)(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getaddrinfo_a_policy");
    if (policy && !policy(mode, list, nitems, sevp))
        abort();
    return getaddrinfo_a(mode, list, nitems, sevp);
}

#include <aliases.h>

#include <aliases.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct aliasent *getaliasbyname_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getaliasbyname_policy");
    if (policy && !policy(name))
        abort();
    return getaliasbyname(name);
}

#include <aliases.h>

#include <aliases.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getaliasbyname_r_wrapper(const char *name, struct aliasent *result, char *buffer, size_t buflen, struct aliasent **res)
{
    typedef bool (*policy_fn_t)(const char *name, struct aliasent *result, char *buffer, size_t buflen, struct aliasent **res);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getaliasbyname_r_policy");
    if (policy && !policy(name, result, buffer, buflen, res))
        abort();
    return getaliasbyname_r(name, result, buffer, buflen, res);
}

#include <aliases.h>

#include <aliases.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct aliasent *getaliasent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getaliasent_policy");
    if (policy && !policy())
        abort();
    return getaliasent();
}

#include <aliases.h>

#include <aliases.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getaliasent_r_wrapper(struct aliasent *result, char *buffer, size_t buflen, struct aliasent **res)
{
    typedef bool (*policy_fn_t)(struct aliasent *result, char *buffer, size_t buflen, struct aliasent **res);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getaliasent_r_policy");
    if (policy && !policy(result, buffer, buflen, res))
        abort();
    return getaliasent_r(result, buffer, buflen, res);
}

#include <sys/auxv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned long getauxval_wrapper(unsigned long type)
{
    typedef bool (*policy_fn_t)(unsigned long type);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getauxval_policy");
    if (policy && !policy(type))
        abort();
    return getauxval(type);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getc_wrapper(FILE *stream)
{
    //wakka printffrom getc\n");
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getc_policy");
    if (policy && !policy(stream))
        abort();
    return getc(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getc_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getc_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return getc_unlocked(stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getchar_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getchar_policy");
    if (policy && !policy())
        abort();
    return getchar();
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getchar_unlocked_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getchar_unlocked_policy");
    if (policy && !policy())
        abort();
    return getchar_unlocked();
}

#include <ucontext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getcontext_wrapper(ucontext_t *ucp)
{
    typedef bool (*policy_fn_t)(ucontext_t *ucp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getcontext_policy");
    if (policy && !policy(ucp))
        abort();
    return getcontext(ucp);
}

// #include <linux/getcpu.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int getcpu_wrapper(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache) {
//     typedef bool (*policy_fn_t)(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getcpu_policy");
//     if(policy && !policy(cpu, node, tcache)) abort();
//     return getcpu(cpu, node, tcache);
// }

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *getcwd_wrapper(char *buf, size_t size)
{
    typedef bool (*policy_fn_t)(char *buf, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getcwd_policy");
    if (policy && !policy(buf, size))
        abort();
    return getcwd(buf, size);
}

#include <time.h>
#include <time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct tm *getdate_wrapper(const char *string)
{
    typedef bool (*policy_fn_t)(const char *string);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdate_policy");
    if (policy && !policy(string))
        abort();
    return getdate(string);
}

#include <time.h>
#include <time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getdate_r_wrapper(const char *string, struct tm *res)
{
    typedef bool (*policy_fn_t)(const char *string, struct tm *res);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdate_r_policy");
    if (policy && !policy(string, res))
        abort();
    return getdate_r(string, res);
}

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t getdelim_wrapper(char **lineptr, size_t *n, int delim, FILE *stream)
{
    typedef bool (*policy_fn_t)(char **lineptr, size_t *n, int delim, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdelim_policy");
    if (policy && !policy(lineptr, n, delim, stream))
        abort();
    return getdelim(lineptr, n, delim, stream);
}

#include <dirent.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t getdents64_wrapper(int fd, void *dirp, size_t count)
{
    typedef bool (*policy_fn_t)(int fd, void *dirp, size_t count);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdents64_policy");
    if (policy && !policy(fd, dirp, count))
        abort();
    return getdents64(fd, dirp, count);
}

#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t getdirentries_wrapper(int fd, char *buf, size_t nbytes, off_t *basep)
{
    typedef bool (*policy_fn_t)(int fd, char *buf, size_t nbytes, off_t *basep);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdirentries_policy");
    if (policy && !policy(fd, buf, nbytes, basep))
        abort();
    return getdirentries(fd, buf, nbytes, basep);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getdomainname_wrapper(char *name, size_t len)
{
    typedef bool (*policy_fn_t)(char *name, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdomainname_policy");
    if (policy && !policy(name, len))
        abort();
    return getdomainname(name, len);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getdtablesize_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getdtablesize_policy");
    if (policy && !policy())
        abort();
    return getdtablesize();
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

gid_t getegid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getegid_policy");
    if (policy && !policy())
        abort();
    return getegid();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getentropy_wrapper(void *buffer, size_t length)
{
    typedef bool (*policy_fn_t)(void *buffer, size_t length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getentropy_policy");
    if (policy && !policy(buffer, length))
        abort();
    return getentropy(buffer, length);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *getenv_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getenv_policy");
    if (policy && !policy(name))
        abort();
    return getenv(name);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uid_t geteuid_wrapper(void)
{
    //wakka printffrom geteuid\n");
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "geteuid_policy");
    if (policy && !policy())
        abort();
    return geteuid();
}

#include <fstab.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct fstab *getfsent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getfsent_policy");
    if (policy && !policy())
        abort();
    return getfsent();
}

#include <fstab.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct fstab *getfsfile_wrapper(const char *mount_point)
{
    typedef bool (*policy_fn_t)(const char *mount_point);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getfsfile_policy");
    if (policy && !policy(mount_point))
        abort();
    return getfsfile(mount_point);
}

#include <fstab.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct fstab *getfsspec_wrapper(const char *special_file)
{
    typedef bool (*policy_fn_t)(const char *special_file);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getfsspec_policy");
    if (policy && !policy(special_file))
        abort();
    return getfsspec(special_file);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

gid_t getgid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgid_policy");
    if (policy && !policy())
        abort();
    return getgid();
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct group *getgrent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrent_policy");
    if (policy && !policy())
        abort();
    return getgrent();
}

#include <grp.h>
#include <grp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getgrent_r_wrapper(struct group *gbuf, char *buf, size_t buflen, struct group **gbufp)
{
    typedef bool (*policy_fn_t)(struct group *gbuf, char *buf, size_t buflen, struct group **gbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrent_r_policy");
    if (policy && !policy(gbuf, buf, buflen, gbufp))
        abort();
    return getgrent_r(gbuf, buf, buflen, gbufp);
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct group *getgrgid_wrapper(gid_t gid)
{
    typedef bool (*policy_fn_t)(gid_t gid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrgid_policy");
    if (policy && !policy(gid))
        abort();
    return getgrgid(gid);
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getgrgid_r_wrapper(gid_t gid, struct group *grp, char *buf, size_t buflen, struct group **result)
{
    typedef bool (*policy_fn_t)(gid_t gid, struct group *grp, char *buf, size_t buflen, struct group **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrgid_r_policy");
    if (policy && !policy(gid, grp, buf, buflen, result))
        abort();
    return getgrgid_r(gid, grp, buf, buflen, result);
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct group *getgrnam_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrnam_policy");
    if (policy && !policy(name))
        abort();
    return getgrnam(name);
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getgrnam_r_wrapper(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result)
{
    typedef bool (*policy_fn_t)(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrnam_r_policy");
    if (policy && !policy(name, grp, buf, buflen, result))
        abort();
    return getgrnam_r(name, grp, buf, buflen, result);
}

#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getgrouplist_wrapper(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
    typedef bool (*policy_fn_t)(const char *user, gid_t group, gid_t *groups, int *ngroups);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgrouplist_policy");
    if (policy && !policy(user, group, groups, ngroups))
        abort();
    return getgrouplist(user, group, groups, ngroups);
}

#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getgroups_wrapper(int size, gid_t list[])
{
    typedef bool (*policy_fn_t)(int size, gid_t list[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getgroups_policy");
    if (policy && !policy(size, list))
        abort();
    return getgroups(size, list);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct hostent *gethostbyaddr_wrapper(const void *addr, socklen_t len, int type)
{
    //wakka printffrom gethostbyaddr\n");
    typedef bool (*policy_fn_t)(const void *addr, socklen_t len, int type);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostbyaddr_policy");
    if (policy && !policy(addr, len, type))
        abort();
    return gethostbyaddr(addr, len, type);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gethostbyaddr_r_wrapper(const void *addr, socklen_t len, int type, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(const void *addr, socklen_t len, int type, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostbyaddr_r_policy");
    if (policy && !policy(addr, len, type, ret, buf, buflen, result, h_errnop))
        abort();
    return gethostbyaddr_r(addr, len, type, ret, buf, buflen, result, h_errnop);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct hostent *gethostbyname_wrapper(const char *name)
{
    //wakka printffrom gethostbyname\n");
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostbyname_policy");
    if (policy && !policy(name))
        abort();
    return gethostbyname(name);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct hostent *gethostbyname2_wrapper(const char *name, int af)
{
    typedef bool (*policy_fn_t)(const char *name, int af);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostbyname2_policy");
    if (policy && !policy(name, af))
        abort();
    return gethostbyname2(name, af);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gethostbyname2_r_wrapper(const char *name, int af, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(const char *name, int af, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostbyname2_r_policy");
    if (policy && !policy(name, af, ret, buf, buflen, result, h_errnop))
        abort();
    return gethostbyname2_r(name, af, ret, buf, buflen, result, h_errnop);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gethostbyname_r_wrapper(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostbyname_r_policy");
    if (policy && !policy(name, ret, buf, buflen, result, h_errnop))
        abort();
    return gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct hostent *gethostent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostent_policy");
    if (policy && !policy())
        abort();
    return gethostent();
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gethostent_r_wrapper(struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostent_r_policy");
    if (policy && !policy(ret, buf, buflen, result, h_errnop))
        abort();
    return gethostent_r(ret, buf, buflen, result, h_errnop);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long gethostid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostid_policy");
    if (policy && !policy())
        abort();
    return gethostid();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gethostname_wrapper(char *name, size_t len)
{
    typedef bool (*policy_fn_t)(char *name, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gethostname_policy");
    if (policy && !policy(name, len))
        abort();
    return gethostname(name, len);
}

#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getifaddrs_wrapper(struct ifaddrs **ifap)
{
    //wakka printffrom getifaddrs\n");
    typedef bool (*policy_fn_t)(struct ifaddrs **ifap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getifaddrs_policy");
    if (policy && !policy(ifap))
        abort();
    return getifaddrs(ifap);
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getitimer_wrapper(int which, struct itimerval *curr_value)
{
    typedef bool (*policy_fn_t)(int which, struct itimerval *curr_value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getitimer_policy");
    if (policy && !policy(which, curr_value))
        abort();
    return getitimer(which, curr_value);
}

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t getline_wrapper(char **lineptr, size_t *n, FILE *stream)
{
    typedef bool (*policy_fn_t)(char **lineptr, size_t *n, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getline_policy");
    if (policy && !policy(lineptr, n, stream))
        abort();
    return getline(lineptr, n, stream);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getloadavg_wrapper(double loadavg[], int nelem)
{
    typedef bool (*policy_fn_t)(double loadavg[], int nelem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getloadavg_policy");
    if (policy && !policy(loadavg, nelem))
        abort();
    return getloadavg(loadavg, nelem);
}

#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *getlogin_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getlogin_policy");
    if (policy && !policy())
        abort();
    return getlogin();
}

#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getlogin_r_wrapper(char *buf, size_t bufsize)
{
    typedef bool (*policy_fn_t)(char *buf, size_t bufsize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getlogin_r_policy");
    if (policy && !policy(buf, bufsize))
        abort();
    return getlogin_r(buf, bufsize);
}

#include <stdio.h>
#include <mntent.h>
#include <mntent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct mntent *getmntent_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getmntent_policy");
    if (policy && !policy(stream))
        abort();
    return getmntent(stream);
}

#include <stdio.h>
#include <mntent.h>
#include <mntent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct mntent *getmntent_r_wrapper(FILE *streamp, struct mntent *mntbuf, char *buf, int buflen)
{
    typedef bool (*policy_fn_t)(FILE *streamp, struct mntent *mntbuf, char *buf, int buflen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getmntent_r_policy");
    if (policy && !policy(streamp, mntbuf, buf, buflen))
        abort();
    return getmntent_r(streamp, mntbuf, buf, buflen);
}

#include <sys/socket.h>
#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getnameinfo_wrapper(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags)
{
    //wakka printffrom getnameinfo\n");
    typedef bool (*policy_fn_t)(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnameinfo_policy");
    if (policy && !policy(addr, addrlen, host, hostlen, serv, servlen, flags))
        abort();
    return getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct netent *getnetbyaddr_wrapper(uint32_t net, int type)
{
    typedef bool (*policy_fn_t)(uint32_t net, int type);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetbyaddr_policy");
    if (policy && !policy(net, type))
        abort();
    return getnetbyaddr(net, type);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getnetbyaddr_r_wrapper(uint32_t net, int type, struct netent *result_buf, char *buf, size_t buflen, struct netent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(uint32_t net, int type, struct netent *result_buf, char *buf, size_t buflen, struct netent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetbyaddr_r_policy");
    if (policy && !policy(net, type, result_buf, buf, buflen, result, h_errnop))
        abort();
    return getnetbyaddr_r(net, type, result_buf, buf, buflen, result, h_errnop);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct netent *getnetbyname_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetbyname_policy");
    if (policy && !policy(name))
        abort();
    return getnetbyname(name);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getnetbyname_r_wrapper(const char *name, struct netent *result_buf, char *buf, size_t buflen, struct netent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(const char *name, struct netent *result_buf, char *buf, size_t buflen, struct netent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetbyname_r_policy");
    if (policy && !policy(name, result_buf, buf, buflen, result, h_errnop))
        abort();
    return getnetbyname_r(name, result_buf, buf, buflen, result, h_errnop);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct netent *getnetent_wrapper(void)
{
    //wakka printffrom getnetent\n");
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetent_policy");
    if (policy && !policy())
        abort();
    return getnetent();
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getnetent_r_wrapper(struct netent *result_buf, char *buf, size_t buflen, struct netent **result, int *h_errnop)
{
    typedef bool (*policy_fn_t)(struct netent *result_buf, char *buf, size_t buflen, struct netent **result, int *h_errnop);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetent_r_policy");
    if (policy && !policy(result_buf, buf, buflen, result, h_errnop))
        abort();
    return getnetent_r(result_buf, buf, buflen, result, h_errnop);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getnetgrent_wrapper(char **host, char **user, char **domain)
{
    typedef bool (*policy_fn_t)(char **host, char **user, char **domain);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetgrent_policy");
    if (policy && !policy(host, user, domain))
        abort();
    return getnetgrent(host, user, domain);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getnetgrent_r_wrapper(char **host, char **user, char **domain, char *buf, size_t buflen)
{
    typedef bool (*policy_fn_t)(char **host, char **user, char **domain, char *buf, size_t buflen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getnetgrent_r_policy");
    if (policy && !policy(host, user, domain, buf, buflen))
        abort();
    return getnetgrent_r(host, user, domain, buf, buflen);
}

#include <unistd.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getopt_wrapper(int argc, char *const argv[], const char *optstring)
{
    typedef bool (*policy_fn_t)(int argc, char *const argv[], const char *optstring);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getopt_policy");
    if (policy && !policy(argc, argv, optstring))
        abort();
    return getopt(argc, argv, optstring);
}

#include <unistd.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getopt_long_wrapper(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex)
{
    typedef bool (*policy_fn_t)(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getopt_long_policy");
    if (policy && !policy(argc, argv, optstring, longopts, longindex))
        abort();
    return getopt_long(argc, argv, optstring, longopts, longindex);
}

#include <unistd.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getopt_long_only_wrapper(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex)
{
    typedef bool (*policy_fn_t)(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getopt_long_only_policy");
    if (policy && !policy(argc, argv, optstring, longopts, longindex))
        abort();
    return getopt_long_only(argc, argv, optstring, longopts, longindex);
}

#include <unistd.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpagesize_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpagesize_policy");
    if (policy && !policy())
        abort();
    return getpagesize();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *getpass_wrapper(const char *prompt)
{
    typedef bool (*policy_fn_t)(const char *prompt);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpass_policy");
    if (policy && !policy(prompt))
        abort();
    return getpass(prompt);
}

#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpeername_wrapper(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    //wakka printffrom getpeername\n");
    typedef bool (*policy_fn_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpeername_policy");
    if (policy && !policy(sockfd, addr, addrlen))
        abort();
    return getpeername(sockfd, addr, addrlen);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t getpgid_wrapper(pid_t pid)
{
    typedef bool (*policy_fn_t)(pid_t pid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpgid_policy");
    if (policy && !policy(pid))
        abort();
    return getpgid(pid);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t getpgrp_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpgrp_policy");
    if (policy && !policy())
        abort();
    return getpgrp();
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t getpid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpid_policy");
    if (policy && !policy())
        abort();
    return getpid();
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t getppid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getppid_policy");
    if (policy && !policy())
        abort();
    return getppid();
}

#include <sys/time.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpriority_wrapper(int which, id_t who)
{
    typedef bool (*policy_fn_t)(int which, id_t who);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpriority_policy");
    if (policy && !policy(which, who))
        abort();
    return getpriority(which, who);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct protoent *getprotobyname_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getprotobyname_policy");
    if (policy && !policy(name))
        abort();
    return getprotobyname(name);
}

#include <netdb.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getprotobyname_r_wrapper(const char *name, struct protoent *result_buf, char *buf, size_t buflen, struct protoent **result)
{
    //wakka printffrom getprotobyname_r\n");

    typedef bool (*policy_fn_t)(const char *name, struct protoent *result_buf, char *buf, size_t buflen, struct protoent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getprotobyname_r_policy");
    if (policy && !policy(name, result_buf, buf, buflen, result))
        abort();
    return getprotobyname_r(name, result_buf, buf, buflen, result);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct protoent *getprotobynumber_wrapper(int proto)
{
    typedef bool (*policy_fn_t)(int proto);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getprotobynumber_policy");
    if (policy && !policy(proto))
        abort();
    return getprotobynumber(proto);
}

#include <netdb.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getprotobynumber_r_wrapper(int proto, struct protoent *result_buf, char *buf, size_t buflen, struct protoent **result)
{
    typedef bool (*policy_fn_t)(int proto, struct protoent *result_buf, char *buf, size_t buflen, struct protoent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getprotobynumber_r_policy");
    if (policy && !policy(proto, result_buf, buf, buflen, result))
        abort();
    return getprotobynumber_r(proto, result_buf, buf, buflen, result);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct protoent *getprotoent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getprotoent_policy");
    if (policy && !policy())
        abort();
    return getprotoent();
}

#include <netdb.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getprotoent_r_wrapper(struct protoent *result_buf, char *buf, size_t buflen, struct protoent **result)
{
    typedef bool (*policy_fn_t)(struct protoent *result_buf, char *buf, size_t buflen, struct protoent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getprotoent_r_policy");
    if (policy && !policy(result_buf, buf, buflen, result))
        abort();
    return getprotoent_r(result_buf, buf, buflen, result);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpt_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpt_policy");
    if (policy && !policy())
        abort();
    return getpt();
}

#include <sys/types.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpw_wrapper(uid_t uid, char *buf)
{
    typedef bool (*policy_fn_t)(uid_t uid, char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpw_policy");
    if (policy && !policy(uid, buf))
        abort();
    return getpw(uid, buf);
}

#include <sys/types.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct passwd *getpwent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpwent_policy");
    if (policy && !policy())
        abort();
    return getpwent();
}

#include <pwd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpwent_r_wrapper(struct passwd *pwbuf, char *buf, size_t buflen, struct passwd **pwbufp)
{
    typedef bool (*policy_fn_t)(struct passwd *pwbuf, char *buf, size_t buflen, struct passwd **pwbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpwent_r_policy");
    if (policy && !policy(pwbuf, buf, buflen, pwbufp))
        abort();
    return getpwent_r(pwbuf, buf, buflen, pwbufp);
}

#include <sys/types.h>
#include <pwd.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct passwd *getpwnam_wrapper(const char *name)
{
    //wakka printffrom getpwnam\n");
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpwnam_policy");
    if (policy && !policy(name))
        abort();
    return getpwnam(name);
}

#include <sys/types.h>
#include <pwd.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpwnam_r_wrapper(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
    typedef bool (*policy_fn_t)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpwnam_r_policy");
    if (policy && !policy(name, pwd, buf, buflen, result))
        abort();
    return getpwnam_r(name, pwd, buf, buflen, result);
}

#include <sys/types.h>
#include <pwd.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct passwd *getpwuid_wrapper(uid_t uid)
{
    typedef bool (*policy_fn_t)(uid_t uid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpwuid_policy");
    if (policy && !policy(uid))
        abort();
    return getpwuid(uid);
}

#include <sys/types.h>
#include <pwd.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getpwuid_r_wrapper(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
    typedef bool (*policy_fn_t)(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getpwuid_r_policy");
    if (policy && !policy(uid, pwd, buf, buflen, result))
        abort();
    return getpwuid_r(uid, pwd, buf, buflen, result);
}

#include <sys/random.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t getrandom_wrapper(void *buf, size_t buflen, unsigned int flags)
{
    typedef bool (*policy_fn_t)(void *buf, size_t buflen, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrandom_policy");
    if (policy && !policy(buf, buflen, flags))
        abort();
    return getrandom(buf, buflen, flags);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getresgid_wrapper(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    typedef bool (*policy_fn_t)(gid_t *rgid, gid_t *egid, gid_t *sgid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getresgid_policy");
    if (policy && !policy(rgid, egid, sgid))
        abort();
    return getresgid(rgid, egid, sgid);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getresuid_wrapper(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    typedef bool (*policy_fn_t)(uid_t *ruid, uid_t *euid, uid_t *suid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getresuid_policy");
    if (policy && !policy(ruid, euid, suid))
        abort();
    return getresuid(ruid, euid, suid);
}

#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getrlimit_wrapper(int resource, struct rlimit *rlim)
{
    typedef bool (*policy_fn_t)(int resource, struct rlimit *rlim);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrlimit_policy");
    if (policy && !policy(resource, rlim))
        abort();
    return getrlimit(resource, rlim);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct rpcent *getrpcbyname_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcbyname_policy");
    if (policy && !policy(name))
        abort();
    return getrpcbyname(name);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getrpcbyname_r_wrapper(const char *name, struct rpcent *result_buf, char *buf, size_t buflen, struct rpcent **result)
{
    typedef bool (*policy_fn_t)(const char *name, struct rpcent *result_buf, char *buf, size_t buflen, struct rpcent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcbyname_r_policy");
    if (policy && !policy(name, result_buf, buf, buflen, result))
        abort();
    return getrpcbyname_r(name, result_buf, buf, buflen, result);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct rpcent *getrpcbynumber_wrapper(int number)
{
    typedef bool (*policy_fn_t)(int number);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcbynumber_policy");
    if (policy && !policy(number))
        abort();
    return getrpcbynumber(number);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getrpcbynumber_r_wrapper(int number, struct rpcent *result_buf, char *buf, size_t buflen, struct rpcent **result)
{
    typedef bool (*policy_fn_t)(int number, struct rpcent *result_buf, char *buf, size_t buflen, struct rpcent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcbynumber_r_policy");
    if (policy && !policy(number, result_buf, buf, buflen, result))
        abort();
    return getrpcbynumber_r(number, result_buf, buf, buflen, result);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct rpcent *getrpcent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcent_policy");
    if (policy && !policy())
        abort();
    return getrpcent();
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getrpcent_r_wrapper(struct rpcent *result_buf, char *buf, size_t buflen, struct rpcent **result)
{
    typedef bool (*policy_fn_t)(struct rpcent *result_buf, char *buf, size_t buflen, struct rpcent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcent_r_policy");
    if (policy && !policy(result_buf, buf, buflen, result))
        abort();
    return getrpcent_r(result_buf, buf, buflen, result);
}

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int getrpcport_wrapper(const char *host, unsigned long prognum, unsigned long versnum, unsigned proto)
// {
//     typedef bool (*policy_fn_t)(const char *host, unsigned long prognum, unsigned long versnum, unsigned proto);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrpcport_policy");
//     if (policy && !policy(host, prognum, versnum, proto))
//         abort();
//     return getrpcport(host, prognum, versnum, proto);
// }

#include <sys/time.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getrusage_wrapper(int who, struct rusage *usage)
{
    typedef bool (*policy_fn_t)(int who, struct rusage *usage);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getrusage_policy");
    if (policy && !policy(who, usage))
        abort();
    return getrusage(who, usage);
}

// #include <stdio.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// char *gets_wrapper(char *s)
// {
//     typedef bool (*policy_fn_t)(char *s);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gets_policy");
//     if (policy && !policy(s))
//         abort();
//     return gets(s);
// }

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct servent *getservbyname_wrapper(const char *name, const char *proto)
{
    //wakka printffrom getservbyname\n");
    typedef bool (*policy_fn_t)(const char *name, const char *proto);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getservbyname_policy");
    if (policy && !policy(name, proto))
        abort();
    return getservbyname(name, proto);
}

#include <netdb.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getservbyname_r_wrapper(const char *name, const char *proto, struct servent *result_buf, char *buf, size_t buflen, struct servent **result)
{
    typedef bool (*policy_fn_t)(const char *name, const char *proto, struct servent *result_buf, char *buf, size_t buflen, struct servent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getservbyname_r_policy");
    if (policy && !policy(name, proto, result_buf, buf, buflen, result))
        abort();
    return getservbyname_r(name, proto, result_buf, buf, buflen, result);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct servent *getservbyport_wrapper(int port, const char *proto)
{
    //wakka printffrom getservbyport\n");
    typedef bool (*policy_fn_t)(int port, const char *proto);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getservbyport_policy");
    if (policy && !policy(port, proto))
        abort();
    return getservbyport(port, proto);
}

#include <netdb.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getservbyport_r_wrapper(int port, const char *proto, struct servent *result_buf, char *buf, size_t buflen, struct servent **result)
{
    typedef bool (*policy_fn_t)(int port, const char *proto, struct servent *result_buf, char *buf, size_t buflen, struct servent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getservbyport_r_policy");
    if (policy && !policy(port, proto, result_buf, buf, buflen, result))
        abort();
    return getservbyport_r(port, proto, result_buf, buf, buflen, result);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct servent *getservent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getservent_policy");
    if (policy && !policy())
        abort();
    return getservent();
}

#include <netdb.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getservent_r_wrapper(struct servent *result_buf, char *buf, size_t buflen, struct servent **result)
{
    typedef bool (*policy_fn_t)(struct servent *result_buf, char *buf, size_t buflen, struct servent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getservent_r_policy");
    if (policy && !policy(result_buf, buf, buflen, result))
        abort();
    return getservent_r(result_buf, buf, buflen, result);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t getsid_wrapper(pid_t pid)
{
    typedef bool (*policy_fn_t)(pid_t pid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getsid_policy");
    if (policy && !policy(pid))
        abort();
    return getsid(pid);
}

#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getsockname_wrapper(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    typedef bool (*policy_fn_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getsockname_policy");
    if (policy && !policy(sockfd, addr, addrlen))
        abort();
    return getsockname(sockfd, addr, addrlen);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getsockopt_wrapper(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    //wakka printffrom getsockopt\n");
    typedef bool (*policy_fn_t)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getsockopt_policy");
    if (policy && !policy(sockfd, level, optname, optval, optlen))
        abort();
    return getsockopt(sockfd, level, optname, optval, optlen);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct spwd *getspent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getspent_policy");
    if (policy && !policy())
        abort();
    return getspent();
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getspent_r_wrapper(struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp)
{
    typedef bool (*policy_fn_t)(struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getspent_r_policy");
    if (policy && !policy(spbuf, buf, buflen, spbufp))
        abort();
    return getspent_r(spbuf, buf, buflen, spbufp);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct spwd *getspnam_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getspnam_policy");
    if (policy && !policy(name))
        abort();
    return getspnam(name);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getspnam_r_wrapper(const char *name, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp)
{
    typedef bool (*policy_fn_t)(const char *name, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getspnam_r_policy");
    if (policy && !policy(name, spbuf, buf, buflen, spbufp))
        abort();
    return getspnam_r(name, spbuf, buf, buflen, spbufp);
}

#include <stdlib.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getsubopt_wrapper(char **optionp, char *const *tokens, char **valuep)
{
    typedef bool (*policy_fn_t)(char **optionp, char *const *tokens, char **valuep);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getsubopt_policy");
    if (policy && !policy(optionp, tokens, valuep))
        abort();
    return getsubopt(optionp, tokens, valuep);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *gettext_wrapper(const char *msgid)
{
    typedef bool (*policy_fn_t)(const char *msgid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gettext_policy");
    if (policy && !policy(msgid))
        abort();
    return gettext(msgid);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t gettid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gettid_policy");
    if (policy && !policy())
        abort();
    return gettid();
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gettimeofday_wrapper(struct timeval *tv, struct timezone *tz)
{
    typedef bool (*policy_fn_t)(struct timeval *tv, struct timezone *tz);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gettimeofday_policy");
    if (policy && !policy(tv, tz))
        abort();
    return gettimeofday(tv, tz);
}

#include <ttyent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct ttyent *getttyent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getttyent_policy");
    if (policy && !policy())
        abort();
    return getttyent();
}

#include <ttyent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct ttyent *getttynam_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getttynam_policy");
    if (policy && !policy(name))
        abort();
    return getttynam(name);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uid_t getuid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getuid_policy");
    if (policy && !policy())
        abort();
    return getuid();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *getusershell_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getusershell_policy");
    if (policy && !policy())
        abort();
    return getusershell();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmp *getutent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutent_policy");
    if (policy && !policy())
        abort();
    return getutent();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getutent_r_wrapper(struct utmp *ubuf, struct utmp **ubufp)
{
    typedef bool (*policy_fn_t)(struct utmp *ubuf, struct utmp **ubufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutent_r_policy");
    if (policy && !policy(ubuf, ubufp))
        abort();
    return getutent_r(ubuf, ubufp);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmp *getutid_wrapper(const struct utmp *ut)
{
    typedef bool (*policy_fn_t)(const struct utmp *ut);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutid_policy");
    if (policy && !policy(ut))
        abort();
    return getutid(ut);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getutid_r_wrapper(struct utmp *ut, struct utmp *ubuf, struct utmp **ubufp)
{
    typedef bool (*policy_fn_t)(struct utmp *ut, struct utmp *ubuf, struct utmp **ubufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutid_r_policy");
    if (policy && !policy(ut, ubuf, ubufp))
        abort();
    return getutid_r(ut, ubuf, ubufp);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmp *getutline_wrapper(const struct utmp *ut)
{
    typedef bool (*policy_fn_t)(const struct utmp *ut);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutline_policy");
    if (policy && !policy(ut))
        abort();
    return getutline(ut);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getutline_r_wrapper(struct utmp *ut, struct utmp *ubuf, struct utmp **ubufp)
{
    typedef bool (*policy_fn_t)(struct utmp *ut, struct utmp *ubuf, struct utmp **ubufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutline_r_policy");
    if (policy && !policy(ut, ubuf, ubufp))
        abort();
    return getutline_r(ut, ubuf, ubufp);
}

#include <utmpx.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void getutmp_wrapper(const struct utmpx *ux, struct utmp *u)
{
    typedef bool (*policy_fn_t)(const struct utmpx *ux, struct utmp *u);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutmp_policy");
    if (policy && !policy(ux, u))
        abort();
    getutmp(ux, u);
}

#include <utmpx.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void getutmpx_wrapper(const struct utmp *u, struct utmpx *ux)
{
    typedef bool (*policy_fn_t)(const struct utmp *u, struct utmpx *ux);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutmpx_policy");
    if (policy && !policy(u, ux))
        abort();
    getutmpx(u, ux);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmpx *getutxent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutxent_policy");
    if (policy && !policy())
        abort();
    return getutxent();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmpx *getutxid_wrapper(const struct utmpx *ut)
{
    typedef bool (*policy_fn_t)(const struct utmpx *);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutxid_policy");
    if (policy && !policy(ut))
        abort();

    return getutxid(ut);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmpx *getutxline_wrapper(const struct utmpx *ut)
{
    typedef bool (*policy_fn_t)(const struct utmpx *);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getutxline_policy");

    if (policy && !policy(ut))
        abort();

    return getutxline(ut);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int getw_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getw_policy");
    if (policy && !policy(stream))
        abort();
    return getw(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t getwc_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getwc_policy");
    if (policy && !policy(stream))
        abort();
    return getwc(stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t getwc_unlocked_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getwc_unlocked_policy");
    if (policy && !policy(stream))
        abort();
    return getwc_unlocked(stream);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t getwchar_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getwchar_policy");
    if (policy && !policy())
        abort();
    return getwchar();
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t getwchar_unlocked_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getwchar_unlocked_policy");
    if (policy && !policy())
        abort();
    return getwchar_unlocked();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *getwd_wrapper(char *buf)
{
    typedef bool (*policy_fn_t)(char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getwd_policy");
    if (policy && !policy(buf))
        abort();
    return getwd(buf);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t getxattr_wrapper(const char *path, const char *name, void *value, size_t size)
{
    typedef bool (*policy_fn_t)(const char *path, const char *name, void *value, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "getxattr_policy");
    if (policy && !policy(path, name, value, size))
        abort();
    return getxattr(path, name, value, size);
}

#include <glob.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int glob_wrapper(const char *pattern, int flags, int (*errfunc)(const char *epath, int eerrno), glob_t *pglob)
{
    typedef bool (*policy_fn_t)(const char *pattern, int flags, int (*errfunc)(const char *epath, int eerrno), glob_t *pglob);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "glob_policy");
    if (policy && !policy(pattern, flags, errfunc, pglob))
        abort();
    return glob(pattern, flags, errfunc, pglob);
}

#include <glob.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void globfree_wrapper(glob_t *pglob)
{
    typedef bool (*policy_fn_t)(glob_t *pglob);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "globfree_policy");
    if (policy && !policy(pglob))
        abort();
    globfree(pglob);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct tm *gmtime_wrapper(const time_t *timep)
{
    typedef bool (*policy_fn_t)(const time_t *timep);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gmtime_policy");
    if (policy && !policy(timep))
        abort();
    return gmtime(timep);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct tm *gmtime_r_wrapper(const time_t *timep, struct tm *result)
{
    typedef bool (*policy_fn_t)(const time_t *timep, struct tm *result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gmtime_r_policy");
    if (policy && !policy(timep, result))
        abort();
    return gmtime_r(timep, result);
}

#include <gnu/libc-version.h>
#include <gnu/libc-version.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *gnu_get_libc_release_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gnu_get_libc_release_policy");
    if (policy && !policy())
        abort();
    return gnu_get_libc_release();
}

#include <gnu/libc-version.h>
#include <gnu/libc-version.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *gnu_get_libc_version_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gnu_get_libc_version_policy");
    if (policy && !policy())
        abort();
    return gnu_get_libc_version();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int grantpt_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "grantpt_policy");
    if (policy && !policy(fd))
        abort();
    return grantpt(fd);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int group_member_wrapper(gid_t gid)
{
    typedef bool (*policy_fn_t)(gid_t gid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "group_member_policy");
    if (policy && !policy(gid))
        abort();
    return group_member(gid);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int gsignal_wrapper(int signum)
{
    typedef bool (*policy_fn_t)(int signum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "gsignal_policy");
    if (policy && !policy(signum))
        abort();
    return gsignal(signum);
}

#include <stdio.h>
#include <mntent.h>
#include <mntent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *hasmntopt_wrapper(const struct mntent *mnt, const char *opt)
{
    typedef bool (*policy_fn_t)(const struct mntent *mnt, const char *opt);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hasmntopt_policy");
    if (policy && !policy(mnt, opt))
        abort();
    return hasmntopt(mnt, opt);
}

#include <search.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int hcreate_wrapper(size_t nel)
{
    typedef bool (*policy_fn_t)(size_t nel);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hcreate_policy");
    if (policy && !policy(nel))
        abort();
    return hcreate(nel);
}

#include <search.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int hcreate_r_wrapper(size_t nel, struct hsearch_data *htab)
{
    typedef bool (*policy_fn_t)(size_t nel, struct hsearch_data *htab);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hcreate_r_policy");
    if (policy && !policy(nel, htab))
        abort();
    return hcreate_r(nel, htab);
}

#include <search.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void hdestroy_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hdestroy_policy");
    if (policy && !policy())
        abort();
    hdestroy();
}

#include <search.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void hdestroy_r_wrapper(struct hsearch_data *htab)
{
    typedef bool (*policy_fn_t)(struct hsearch_data *htab);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hdestroy_r_policy");
    if (policy && !policy(htab))
        abort();
    hdestroy_r(htab);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void herror_wrapper(const char *s)
{
    typedef bool (*policy_fn_t)(const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "herror_policy");
    if (policy && !policy(s))
        abort();
    herror(s);
}

#include <search.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ENTRY *hsearch_wrapper(ENTRY item, ACTION action)
{
    typedef bool (*policy_fn_t)(ENTRY item, ACTION action);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hsearch_policy");
    if (policy && !policy(item, action))
        abort();
    return hsearch(item, action);
}

#include <search.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int hsearch_r_wrapper(ENTRY item, ACTION action, ENTRY **retval, struct hsearch_data *htab)
{
    typedef bool (*policy_fn_t)(ENTRY item, ACTION action, ENTRY **retval, struct hsearch_data *htab);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hsearch_r_policy");
    if (policy && !policy(item, action, retval, htab))
        abort();
    return hsearch_r(item, action, retval, htab);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *hstrerror_wrapper(int err)
{
    typedef bool (*policy_fn_t)(int err);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "hstrerror_policy");
    if (policy && !policy(err))
        abort();
    return hstrerror(err);
}

#include <arpa/inet.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uint32_t htonl_wrapper(uint32_t hostlong)
{
    typedef bool (*policy_fn_t)(uint32_t hostlong);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "htonl_policy");
    if (policy && !policy(hostlong))
        abort();
    return htonl(hostlong);
}

#include <arpa/inet.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uint16_t htons_wrapper(uint16_t hostshort)
{
    typedef bool (*policy_fn_t)(uint16_t hostshort);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "htons_policy");
    if (policy && !policy(hostshort))
        abort();
    return htons(hostshort);
}

#include <iconv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t iconv_wrapper(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)
{
    typedef bool (*policy_fn_t)(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iconv_policy");
    if (policy && !policy(cd, inbuf, inbytesleft, outbuf, outbytesleft))
        abort();
    return iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft);
}

#include <iconv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iconv_close_wrapper(iconv_t cd)
{
    typedef bool (*policy_fn_t)(iconv_t cd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iconv_close_policy");
    if (policy && !policy(cd))
        abort();
    return iconv_close(cd);
}

#include <iconv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

iconv_t iconv_open_wrapper(const char *tocode, const char *fromcode)
{
    typedef bool (*policy_fn_t)(const char *tocode, const char *fromcode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iconv_open_policy");
    if (policy && !policy(tocode, fromcode))
        abort();
    return iconv_open(tocode, fromcode);
}

#include <net/if.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void if_freenameindex_wrapper(struct if_nameindex *ptr)
{
    typedef bool (*policy_fn_t)(struct if_nameindex *ptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "if_freenameindex_policy");
    if (policy && !policy(ptr))
        abort();
    if_freenameindex(ptr);
}

#include <net/if.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *if_indextoname_wrapper(unsigned int ifindex, char *ifname)
{
    typedef bool (*policy_fn_t)(unsigned int ifindex, char *ifname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "if_indextoname_policy");
    if (policy && !policy(ifindex, ifname))
        abort();
    return if_indextoname(ifindex, ifname);
}

// Could not parse: struct if_nameindex *if_nameindex(void)

#include <net/if.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned int if_nametoindex_wrapper(const char *ifname)
{
    typedef bool (*policy_fn_t)(const char *ifname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "if_nametoindex_policy");
    if (policy && !policy(ifname))
        abort();
    return if_nametoindex(ifname);
}

#include <stdlib.h>
#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

intmax_t imaxabs_wrapper(intmax_t j)
{
    typedef bool (*policy_fn_t)(intmax_t j);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "imaxabs_policy");
    if (policy && !policy(j))
        abort();
    return imaxabs(j);
}

// Could not parse: imaxdiv_t imaxdiv(intmax_t numerator, intmax_t denominator)

#include <strings.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>
const char *index_wrapper(const char *s, int c)
{
    typedef bool (*policy_fn_t)(const char *, int);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "index_policy");
    if (policy && !policy(s, c))
        abort();

    return strchr(s, c);   // index() == strchr()
}


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

in_addr_t inet_addr_wrapper(const char *cp)
{
    typedef bool (*policy_fn_t)(const char *cp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_addr_policy");
    if (policy && !policy(cp))
        abort();
    return inet_addr(cp);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int inet_aton_wrapper(const char *cp, struct in_addr *inp)
{
    typedef bool (*policy_fn_t)(const char *cp, struct in_addr *inp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_aton_policy");
    if (policy && !policy(cp, inp))
        abort();
    return inet_aton(cp, inp);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

in_addr_t inet_lnaof_wrapper(struct in_addr in)
{
    typedef bool (*policy_fn_t)(struct in_addr in);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_lnaof_policy");
    if (policy && !policy(in))
        abort();
    return inet_lnaof(in);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct in_addr inet_makeaddr_wrapper(in_addr_t net, in_addr_t host)
{
    typedef bool (*policy_fn_t)(in_addr_t net, in_addr_t host);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_makeaddr_policy");
    if (policy && !policy(net, host))
        abort();
    return inet_makeaddr(net, host);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

in_addr_t inet_netof_wrapper(struct in_addr in)
{
    typedef bool (*policy_fn_t)(struct in_addr in);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_netof_policy");
    if (policy && !policy(in))
        abort();
    return inet_netof(in);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

in_addr_t inet_network_wrapper(const char *cp)
{
    typedef bool (*policy_fn_t)(const char *cp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_network_policy");
    if (policy && !policy(cp))
        abort();
    return inet_network(cp);
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *inet_ntoa_wrapper(struct in_addr in)
{
    typedef bool (*policy_fn_t)(struct in_addr in);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_ntoa_policy");
    if (policy && !policy(in))
        abort();
    return inet_ntoa(in);
}

#include <arpa/inet.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *inet_ntop_wrapper(int af, const void *src, char *dst, socklen_t size)
{
    typedef bool (*policy_fn_t)(int af, const void *src, char *dst, socklen_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_ntop_policy");
    if (policy && !policy(af, src, dst, size))
        abort();
    return inet_ntop(af, src, dst, size);
}

#include <arpa/inet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int inet_pton_wrapper(int af, const char *src, void *dst)
{
    typedef bool (*policy_fn_t)(int af, const char *src, void *dst);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inet_pton_policy");
    if (policy && !policy(af, src, dst))
        abort();
    return inet_pton(af, src, dst);
}

// #include <linux/module.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int init_module_wrapper(void *module_image, unsigned long len, const char *param_values)
// {
//     typedef bool (*policy_fn_t)(void *module_image, unsigned long len, const char *param_values);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "init_module_policy");
//     if (policy && !policy(module_image, len, param_values))
//         abort();
//     return init_module(module_image, len, param_values);
// }

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int initgroups_wrapper(const char *user, gid_t group)
{
    typedef bool (*policy_fn_t)(const char *user, gid_t group);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "initgroups_policy");
    if (policy && !policy(user, group))
        abort();
    return initgroups(user, group);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *initstate_wrapper(unsigned seed, char *state, size_t n)
{
    typedef bool (*policy_fn_t)(unsigned seed, char *state, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "initstate_policy");
    if (policy && !policy(seed, state, n))
        abort();
    return initstate(seed, state, n);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int initstate_r_wrapper(unsigned int seed, char *statebuf, size_t statelen, struct random_data *buf)
{
    typedef bool (*policy_fn_t)(unsigned int seed, char *statebuf, size_t statelen, struct random_data *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "initstate_r_policy");
    if (policy && !policy(seed, statebuf, statelen, buf))
        abort();
    return initstate_r(seed, statebuf, statelen, buf);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int innetgr_wrapper(const char *netgroup, const char *host, const char *user, const char *domain)
{
    typedef bool (*policy_fn_t)(const char *netgroup, const char *host, const char *user, const char *domain);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "innetgr_policy");
    if (policy && !policy(netgroup, host, user, domain))
        abort();
    return innetgr(netgroup, host, user, domain);
}

#include <sys/inotify.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int inotify_add_watch_wrapper(int fd, const char *pathname, uint32_t mask)
{
    typedef bool (*policy_fn_t)(int fd, const char *pathname, uint32_t mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inotify_add_watch_policy");
    if (policy && !policy(fd, pathname, mask))
        abort();
    return inotify_add_watch(fd, pathname, mask);
}

#include <sys/inotify.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int inotify_init_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inotify_init_policy");
    if (policy && !policy())
        abort();
    return inotify_init();
}

#include <sys/inotify.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int inotify_init1_wrapper(int flags)
{
    typedef bool (*policy_fn_t)(int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inotify_init1_policy");
    if (policy && !policy(flags))
        abort();
    return inotify_init1(flags);
}

#include <sys/inotify.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int inotify_rm_watch_wrapper(int fd, int wd)
{
    typedef bool (*policy_fn_t)(int fd, int wd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "inotify_rm_watch_policy");
    if (policy && !policy(fd, wd))
        abort();
    return inotify_rm_watch(fd, wd);
}

#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void insque_wrapper(void *elem, void *prev)
{
    typedef bool (*policy_fn_t)(void *elem, void *prev);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "insque_policy");
    if (policy && !policy(elem, prev))
        abort();
    insque(elem, prev);
}

#include <sys/ioctl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ioctl_wrapper(int fd, unsigned long request, ...)
{
    //wakka printffrom ioctl\n");
    va_list args;
    va_start(args, request);

    long var_argv[1];
    var_argv[0] = va_arg(args, long);

    typedef bool (*policy_fn_t)(int, long[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ioctl_policy");
    if (policy && !policy(fd, var_argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return ioctl(fd, var_argv[0]);
}

#include <sys/io.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ioperm_wrapper(unsigned long from, unsigned long num, int turn_on)
{
    typedef bool (*policy_fn_t)(unsigned long from, unsigned long num, int turn_on);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ioperm_policy");
    if (policy && !policy(from, num, turn_on))
        abort();
    return ioperm(from, num, turn_on);
}

#include <sys/io.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iopl_wrapper(int level)
{
    typedef bool (*policy_fn_t)(int level);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iopl_policy");
    if (policy && !policy(level))
        abort();
    return iopl(level);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iruserok_wrapper(uint32_t raddr, int superuser, const char *ruser, const char *luser)
{
    typedef bool (*policy_fn_t)(uint32_t raddr, int superuser, const char *ruser, const char *luser);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iruserok_policy");
    if (policy && !policy(raddr, superuser, ruser, luser))
        abort();
    return iruserok(raddr, superuser, ruser, luser);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iruserok_af_wrapper(const void *raddr, int superuser, const char *ruser, const char *luser, sa_family_t af)
{
    typedef bool (*policy_fn_t)(const void *raddr, int superuser, const char *ruser, const char *luser, sa_family_t af);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iruserok_af_policy");
    if (policy && !policy(raddr, superuser, ruser, luser, af))
        abort();
    return iruserok_af(raddr, superuser, ruser, luser, af);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isalnum_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isalnum_policy");
    if (policy && !policy(c))
        abort();
    return isalnum(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isalnum_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isalnum_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isalnum_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isalpha_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isalpha_policy");
    if (policy && !policy(c))
        abort();
    return isalpha(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isalpha_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isalpha_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isalpha_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isascii_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isascii_policy");
    if (policy && !policy(c))
        abort();
    return isascii(c);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isatty_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isatty_policy");
    if (policy && !policy(fd))
        abort();
    return isatty(fd);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isblank_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isblank_policy");
    if (policy && !policy(c))
        abort();
    return isblank(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isblank_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isblank_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isblank_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iscntrl_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iscntrl_policy");
    if (policy && !policy(c))
        abort();
    return iscntrl(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iscntrl_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iscntrl_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return iscntrl_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isdigit_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isdigit_policy");
    if (policy && !policy(c))
        abort();
    return isdigit(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isdigit_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isdigit_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isdigit_l(c, locale);
}

#include <sys/stat.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isfdtype_wrapper(int fd, int fdtype)
{
    typedef bool (*policy_fn_t)(int fd, int fdtype);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isfdtype_policy");
    if (policy && !policy(fd, fdtype))
        abort();
    return isfdtype(fd, fdtype);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isgraph_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isgraph_policy");
    if (policy && !policy(c))
        abort();
    return isgraph(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isgraph_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isgraph_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isgraph_l(c, locale);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isinf_wrapper(double x)
{
    typedef bool (*policy_fn_t)(double);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isinf_policy");

    if (policy && !policy(x))
        abort();

    return isinf(x);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isinff_wrapper(float x)
{
    typedef bool (*policy_fn_t)(float x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isinff_policy");
    if (policy && !policy(x))
        abort();
    return isinff(x);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isinfl_wrapper(long double x)
{
    typedef bool (*policy_fn_t)(long double x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isinfl_policy");
    if (policy && !policy(x))
        abort();
    return isinfl(x);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int islower_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "islower_policy");
    if (policy && !policy(c))
        abort();
    return islower(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int islower_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "islower_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return islower_l(c, locale);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isnan_wrapper(double x)
{
    typedef bool (*policy_fn_t)(double);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isnan_policy");

    if (policy && !policy(x))
        abort();

    return isnan(x);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isnanf_wrapper(float x)
{
    typedef bool (*policy_fn_t)(float x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isnanf_policy");
    if (policy && !policy(x))
        abort();
    return isnanf(x);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isnanl_wrapper(long double x)
{
    typedef bool (*policy_fn_t)(long double x);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isnanl_policy");
    if (policy && !policy(x))
        abort();
    return isnanl(x);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isprint_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isprint_policy");
    if (policy && !policy(c))
        abort();
    return isprint(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isprint_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isprint_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isprint_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ispunct_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ispunct_policy");
    if (policy && !policy(c))
        abort();
    return ispunct(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ispunct_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ispunct_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return ispunct_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isspace_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isspace_policy");
    if (policy && !policy(c))
        abort();
    return isspace(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isspace_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isspace_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isspace_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isupper_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isupper_policy");
    if (policy && !policy(c))
        abort();
    return isupper(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isupper_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isupper_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isupper_l(c, locale);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswalnum_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswalnum_policy");
    if (policy && !policy(wc))
        abort();
    return iswalnum(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswalpha_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswalpha_policy");
    if (policy && !policy(wc))
        abort();
    return iswalpha(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswblank_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswblank_policy");
    if (policy && !policy(wc))
        abort();
    return iswblank(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswcntrl_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswcntrl_policy");
    if (policy && !policy(wc))
        abort();
    return iswcntrl(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswctype_wrapper(wint_t wc, wctype_t desc)
{
    typedef bool (*policy_fn_t)(wint_t wc, wctype_t desc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswctype_policy");
    if (policy && !policy(wc, desc))
        abort();
    return iswctype(wc, desc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswdigit_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswdigit_policy");
    if (policy && !policy(wc))
        abort();
    return iswdigit(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswgraph_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswgraph_policy");
    if (policy && !policy(wc))
        abort();
    return iswgraph(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswlower_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswlower_policy");
    if (policy && !policy(wc))
        abort();
    return iswlower(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswprint_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswprint_policy");
    if (policy && !policy(wc))
        abort();
    return iswprint(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswpunct_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswpunct_policy");
    if (policy && !policy(wc))
        abort();
    return iswpunct(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswspace_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswspace_policy");
    if (policy && !policy(wc))
        abort();
    return iswspace(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswupper_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswupper_policy");
    if (policy && !policy(wc))
        abort();
    return iswupper(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int iswxdigit_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "iswxdigit_policy");
    if (policy && !policy(wc))
        abort();
    return iswxdigit(wc);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isxdigit_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isxdigit_policy");
    if (policy && !policy(c))
        abort();
    return isxdigit(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int isxdigit_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "isxdigit_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return isxdigit_l(c, locale);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long jrand48_wrapper(unsigned short xsubi[3])
{
    typedef bool (*policy_fn_t)(unsigned short xsubi[3]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "jrand48_policy");

    if (policy && !policy(xsubi))
        abort();

    return jrand48(xsubi);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int jrand48_r_wrapper(unsigned short xsubi[3],
                      struct drand48_data *buffer,
                      long *result)
{
    typedef bool (*policy_fn_t)(unsigned short xsubi[3],
                                struct drand48_data *buffer,
                                long *result);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "jrand48_r_policy");

    if (policy && !policy(xsubi, buffer, result))
        abort();

    return jrand48_r(xsubi, buffer, result);
}


// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int key_decryptsession_wrapper(char *remotename, des_block *deskey)
{
    typedef bool (*policy_fn_t)(char *remotename, des_block *deskey);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "key_decryptsession_policy");
    if (policy && !policy(remotename, deskey))
        abort();
    return key_decryptsession(remotename, deskey);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int key_encryptsession_wrapper(char *remotename, des_block *deskey)
{
    typedef bool (*policy_fn_t)(char *remotename, des_block *deskey);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "key_encryptsession_policy");
    if (policy && !policy(remotename, deskey))
        abort();
    return key_encryptsession(remotename, deskey);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int key_gendes_wrapper(des_block *deskey)
{
    typedef bool (*policy_fn_t)(des_block *deskey);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "key_gendes_policy");
    if (policy && !policy(deskey))
        abort();
    return key_gendes(deskey);
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int key_secretkey_is_set_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "key_secretkey_is_set_policy");
    if (policy && !policy())
        abort();
    return key_secretkey_is_set();
}

// // #include <rpc/rpc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int key_setsecret_wrapper(char *key)
{
    typedef bool (*policy_fn_t)(char *key);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "key_setsecret_policy");
    if (policy && !policy(key))
        abort();
    return key_setsecret(key);
}

#include <sys/types.h>
#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int kill_wrapper(pid_t pid, int sig)
{
    //wakka printffrom kill\n");
    typedef bool (*policy_fn_t)(pid_t pid, int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "kill_policy");
    if (policy && !policy(pid, sig))
        abort();
    return kill(pid, sig);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int killpg_wrapper(int pgrp, int sig)
{
    typedef bool (*policy_fn_t)(int pgrp, int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "killpg_policy");
    if (policy && !policy(pgrp, sig))
        abort();
    return killpg(pgrp, sig);
}

#include <sys/klog.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int klogctl_wrapper(int type, char *bufp, int len)
{
    typedef bool (*policy_fn_t)(int type, char *bufp, int len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "klogctl_policy");
    if (policy && !policy(type, bufp, len))
        abort();
    return klogctl(type, bufp, len);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *l64a_wrapper(long value)
{
    typedef bool (*policy_fn_t)(long value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "l64a_policy");
    if (policy && !policy(value))
        abort();
    return l64a(value);
}

#include <stdlib.h>
#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long labs_wrapper(long j)
{
    typedef bool (*policy_fn_t)(long j);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "labs_policy");
    if (policy && !policy(j))
        abort();
    return labs(j);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lchown_wrapper(const char *pathname, uid_t owner, gid_t group)
{
    typedef bool (*policy_fn_t)(const char *pathname, uid_t owner, gid_t group);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lchown_policy");
    if (policy && !policy(pathname, owner, group))
        abort();
    return lchown(pathname, owner, group);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lckpwdf_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lckpwdf_policy");
    if (policy && !policy())
        abort();
    return lckpwdf();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void lcong48_wrapper(unsigned short param[7])
{
    typedef bool (*policy_fn_t)(unsigned short param[7]);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "lcong48_policy");
    if (policy && !policy(param))
        abort();

    lcong48(param);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lcong48_r_wrapper(unsigned short param[7], struct drand48_data *buffer)
{
    typedef bool (*policy_fn_t)(unsigned short param[7], struct drand48_data *buffer);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "lcong48_r_policy");

    if (policy && !policy(param, buffer))
        abort();

    return lcong48_r(param, buffer);
}


#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double ldexp_wrapper(double x, int exp)
{
    typedef bool (*policy_fn_t)(double x, int exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ldexp_policy");
    if (policy && !policy(x, exp))
        abort();
    return ldexp(x, exp);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

float ldexpf_wrapper(float x, int exp)
{
    typedef bool (*policy_fn_t)(float x, int exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ldexpf_policy");
    if (policy && !policy(x, exp))
        abort();
    return ldexpf(x, exp);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long double ldexpl_wrapper(long double x, int exp)
{
    typedef bool (*policy_fn_t)(long double x, int exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ldexpl_policy");
    if (policy && !policy(x, exp))
        abort();
    return ldexpl(x, exp);
}

// Could not parse: ldiv_t ldiv(long numerator, long denominator)

#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *lfind_wrapper(const void *key, const void *base, size_t *nmemb, size_t size, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(const void *key, const void *base, size_t *nmemb, size_t size, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lfind_policy");
    if (policy && !policy(key, base, nmemb, size, compar))
        abort();
    return lfind(key, base, nmemb, size, compar);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t lgetxattr_wrapper(const char *path, const char *name, void *value, size_t size)
{
    typedef bool (*policy_fn_t)(const char *path, const char *name, void *value, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lgetxattr_policy");
    if (policy && !policy(path, name, value, size))
        abort();
    return lgetxattr(path, name, value, size);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int link_wrapper(const char *oldpath, const char *newpath)
{
    //wakka printffrom link\n");
    typedef bool (*policy_fn_t)(const char *oldpath, const char *newpath);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "link_policy");
    if (policy && !policy(oldpath, newpath))
        abort();
    return link(oldpath, newpath);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int linkat_wrapper(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    typedef bool (*policy_fn_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "linkat_policy");
    if (policy && !policy(olddirfd, oldpath, newdirfd, newpath, flags))
        abort();
    return linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

#include <aio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lio_listio_wrapper(int mode, struct aiocb *const aiocb_list[], int nitems, struct sigevent *sevp)
{
    typedef bool (*policy_fn_t)(int mode, struct aiocb *const aiocb_list[], int nitems, struct sigevent *sevp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lio_listio_policy");
    if (policy && !policy(mode, aiocb_list, nitems, sevp))
        abort();
    return lio_listio(mode, aiocb_list, nitems, sevp);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int listen_wrapper(int sockfd, int backlog)
{
    //wakka printffrom listen\n");
    typedef bool (*policy_fn_t)(int sockfd, int backlog);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "listen_policy");
    if (policy && !policy(sockfd, backlog))
        abort();
    return listen(sockfd, backlog);
}

#include <sys/types.h>
#include <sys/xattr.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t listxattr_wrapper(const char *path, char *list, size_t size)
{
    typedef bool (*policy_fn_t)(const char *path, char *list, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "listxattr_policy");
    if (policy && !policy(path, list, size))
        abort();
    return listxattr(path, list, size);
}

#include <stdlib.h>
#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long long llabs_wrapper(long long j)
{
    typedef bool (*policy_fn_t)(long long j);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "llabs_policy");
    if (policy && !policy(j))
        abort();
    return llabs(j);
}

// Could not parse: lldiv_t lldiv(long long numerator, long long denominator)

#include <sys/types.h>
#include <sys/xattr.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t llistxattr_wrapper(const char *path, char *list, size_t size)
{
    typedef bool (*policy_fn_t)(const char *path, char *list, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "llistxattr_policy");
    if (policy && !policy(path, list, size))
        abort();
    return llistxattr(path, list, size);
}

// #include <sys/types.h>
// #include <unistd.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int llseek_wrapper(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, unsigned int whence)
// {
//     typedef bool (*policy_fn_t)(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, unsigned int whence);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "llseek_policy");
//     if (policy && !policy(fd, offset_high, offset_low, result, whence))
//         abort();
//     return llseek(fd, offset_high, offset_low, result, whence);
// }

#include <locale.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct lconv *localeconv_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "localeconv_policy");
    if (policy && !policy())
        abort();
    return localeconv();
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct tm *localtime_wrapper(const time_t *timep)
{
    typedef bool (*policy_fn_t)(const time_t *timep);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "localtime_policy");
    if (policy && !policy(timep))
        abort();
    return localtime(timep);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct tm *localtime_r_wrapper(const time_t *timep, struct tm *result)
{
    typedef bool (*policy_fn_t)(const time_t *timep, struct tm *result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "localtime_r_policy");
    if (policy && !policy(timep, result))
        abort();
    return localtime_r(timep, result);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lockf_wrapper(int fd, int cmd, off_t len)
{
    typedef bool (*policy_fn_t)(int fd, int cmd, off_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lockf_policy");
    if (policy && !policy(fd, cmd, len))
        abort();
    return lockf(fd, cmd, len);
}

#include <utmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void login_wrapper(const struct utmp *ut)
{
    typedef bool (*policy_fn_t)(const struct utmp *ut);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "login_policy");
    if (policy && !policy(ut))
        abort();
    login(ut);
}

#include <pty.h>
#include <utmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int login_tty_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "login_tty_policy");
    if (policy && !policy(fd))
        abort();
    return login_tty(fd);
}

#include <utmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int logout_wrapper(const char *ut_line)
{
    typedef bool (*policy_fn_t)(const char *ut_line);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "logout_policy");
    if (policy && !policy(ut_line))
        abort();
    return logout(ut_line);
}

#include <utmp.h>
#include <utmpx.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void logwtmp_wrapper(const char *line, const char *name, const char *host)
{
    typedef bool (*policy_fn_t)(const char *line, const char *name, const char *host);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "logwtmp_policy");
    if (policy && !policy(line, name, host))
        abort();
    logwtmp(line, name, host);
}

#include <setjmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void longjmp_wrapper(jmp_buf env, int val)
{
    typedef bool (*policy_fn_t)(jmp_buf env, int val);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "longjmp_policy");
    if (policy && !policy(env, val))
        abort();
    longjmp(env, val);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long lrand48_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lrand48_policy");
    if (policy && !policy())
        abort();
    return lrand48();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lrand48_r_wrapper(struct drand48_data *buffer, long *result)
{
    typedef bool (*policy_fn_t)(struct drand48_data *buffer, long *result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lrand48_r_policy");
    if (policy && !policy(buffer, result))
        abort();
    return lrand48_r(buffer, result);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lremovexattr_wrapper(const char *path, const char *name)
{
    typedef bool (*policy_fn_t)(const char *path, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lremovexattr_policy");
    if (policy && !policy(path, name))
        abort();
    return lremovexattr(path, name);
}

#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *lsearch_wrapper(const void *key, void *base, size_t *nmemb, size_t size, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(const void *key, void *base, size_t *nmemb, size_t size, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lsearch_policy");
    if (policy && !policy(key, base, nmemb, size, compar))
        abort();
    return lsearch(key, base, nmemb, size, compar);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

off_t lseek_wrapper(int fd, off_t offset, int whence)
{
    //wakka printffrom lseek\n");
    typedef bool (*policy_fn_t)(int fd, off_t offset, int whence);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lseek_policy");
    if (policy && !policy(fd, offset, whence))
        abort();
    return lseek(fd, offset, whence);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

off64_t lseek64_wrapper(int fd, off64_t offset, int whence)
{
    typedef bool (*policy_fn_t)(int fd, off64_t offset, int whence);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lseek64_policy");
    if (policy && !policy(fd, offset, whence))
        abort();
    return lseek64(fd, offset, whence);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lsetxattr_wrapper(const char *path, const char *name, const void *value, size_t size, int flags)
{
    typedef bool (*policy_fn_t)(const char *path, const char *name, const void *value, size_t size, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lsetxattr_policy");
    if (policy && !policy(path, name, value, size, flags))
        abort();
    return lsetxattr(path, name, value, size, flags);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lstat_wrapper(const char *pathname, struct stat *statbuf)
{
    typedef bool (*policy_fn_t)(const char *pathname, struct stat *statbuf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lstat_policy");
    if (policy && !policy(pathname, statbuf))
        abort();
    return lstat(pathname, statbuf);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lstat64_wrapper(const char *pathname, struct stat *statbuf)
{
    typedef bool (*policy_fn_t)(const char *, struct stat *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "lstat64_policy");
    if (policy && !policy(pathname, statbuf))
        abort();

    return lstat(pathname, statbuf);   // <-- modern API
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int lutimes_wrapper(const char *filename, const struct timeval tv[2])
{
    typedef bool (*policy_fn_t)(const char *filename, const struct timeval tv[2]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "lutimes_policy");
    if (policy && !policy(filename, tv))
        abort();
    return lutimes(filename, tv);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int madvise_wrapper(void *addr, size_t length, int advice)
{
    typedef bool (*policy_fn_t)(void *addr, size_t length, int advice);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "madvise_policy");
    if (policy && !policy(addr, length, advice))
        abort();
    return madvise(addr, length, advice);
}

#include <ucontext.h>
#include <ucontext.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void makecontext_wrapper(ucontext_t *ucp, void (*func)(), int argc, ...)
{
    //wakka printffrom makecontext\n");
    va_list args;
    va_start(args, argc);
    unsigned long var_argv[64] = {0};
    for (int i = 0; i < argc && i < 64; i++)
        var_argv[i] = (unsigned long)va_arg(args, int);
    va_end(args);

    typedef bool (*policy_fn_t)(ucontext_t *ucp, void (*func)(), int argc, unsigned long var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "makecontext_policy");
    if (policy && !policy(ucp, func, argc, var_argv))
        abort();

    switch (argc)
    {
    case 0:
        makecontext(ucp, func, argc);
        break;
    case 1:
        makecontext(ucp, func, argc, (int)var_argv[0]);
        break;
    case 2:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1]);
        break;
    case 3:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2]);
        break;
    case 4:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3]);
        break;
    case 5:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3], (int)var_argv[4]);
        break;
    case 6:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3], (int)var_argv[4], (int)var_argv[5]);
        break;
    case 7:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3], (int)var_argv[4], (int)var_argv[5], (int)var_argv[6]);
        break;
    case 8:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3], (int)var_argv[4], (int)var_argv[5], (int)var_argv[6], (int)var_argv[7]);
        break;
    case 9:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3], (int)var_argv[4], (int)var_argv[5], (int)var_argv[6], (int)var_argv[7], (int)var_argv[8]);
        break;
    case 10:
        makecontext(ucp, func, argc, (int)var_argv[0], (int)var_argv[1], (int)var_argv[2], (int)var_argv[3], (int)var_argv[4], (int)var_argv[5], (int)var_argv[6], (int)var_argv[7], (int)var_argv[8], (int)var_argv[9]);
        break;
    }
}

// Could not parse: struct mallinfo mallinfo(void)

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *malloc_wrapper(size_t size)
{
    typedef bool (*policy_fn_t)(size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "malloc_policy");
    if (policy && !policy(size))
        abort();
    return malloc(size);
}

#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <malloc.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int malloc_info_wrapper(int options, FILE *stream)
{
    typedef bool (*policy_fn_t)(int options, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "malloc_info_policy");
    if (policy && !policy(options, stream))
        abort();
    return malloc_info(options, stream);
}

#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void malloc_stats_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "malloc_stats_policy");
    if (policy && !policy())
        abort();
    malloc_stats();
}

#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int malloc_trim_wrapper(size_t pad)
{
    typedef bool (*policy_fn_t)(size_t pad);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "malloc_trim_policy");
    if (policy && !policy(pad))
        abort();
    return malloc_trim(pad);
}

#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t malloc_usable_size_wrapper(void *ptr)
{
    typedef bool (*policy_fn_t)(void *ptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "malloc_usable_size_policy");
    if (policy && !policy(ptr))
        abort();
    return malloc_usable_size(ptr);
}

#include <malloc.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mallopt_wrapper(int param, int value)
{
    typedef bool (*policy_fn_t)(int param, int value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mallopt_policy");
    if (policy && !policy(param, value))
        abort();
    return mallopt(param, value);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mblen_wrapper(const char *s, size_t n)
{
    typedef bool (*policy_fn_t)(const char *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mblen_policy");
    if (policy && !policy(s, n))
        abort();
    return mblen(s, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t mbrlen_wrapper(const char *s, size_t n, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(const char *s, size_t n, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbrlen_policy");
    if (policy && !policy(s, n, ps))
        abort();
    return mbrlen(s, n, ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t mbrtowc_wrapper(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbrtowc_policy");
    if (policy && !policy(pwc, s, n, ps))
        abort();
    return mbrtowc(pwc, s, n, ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mbsinit_wrapper(const mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(const mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbsinit_policy");
    if (policy && !policy(ps))
        abort();
    return mbsinit(ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t mbsnrtowcs_wrapper(wchar_t *dest, const char **src, size_t nms, size_t len, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const char **src, size_t nms, size_t len, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbsnrtowcs_policy");
    if (policy && !policy(dest, src, nms, len, ps))
        abort();
    return mbsnrtowcs(dest, src, nms, len, ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t mbsrtowcs_wrapper(wchar_t *dest, const char **src, size_t len, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const char **src, size_t len, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbsrtowcs_policy");
    if (policy && !policy(dest, src, len, ps))
        abort();
    return mbsrtowcs(dest, src, len, ps);
}

#include <stdlib.h>
#include <wctype.h>
#include <locale.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t mbstowcs_wrapper(wchar_t *dest, const char *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const char *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbstowcs_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return mbstowcs(dest, src, n);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mbtowc_wrapper(wchar_t *pwc, const char *s, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *pwc, const char *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mbtowc_policy");
    if (policy && !policy(pwc, s, n))
        abort();
    return mbtowc(pwc, s, n);
}

#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>
#include <mcheck.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mcheck_wrapper(void (*abortfunc)(enum mcheck_status mstatus))
{
    typedef bool (*policy_fn_t)(void (*abortfunc)(enum mcheck_status mstatus));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mcheck_policy");
    if (policy && !policy(abortfunc))
        abort();
    return mcheck(abortfunc);
}

#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>
#include <mcheck.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void mcheck_check_all_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mcheck_check_all_policy");
    if (policy && !policy())
        abort();
    mcheck_check_all();
}

#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>
#include <mcheck.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mcheck_pedantic_wrapper(void (*abortfunc)(enum mcheck_status mstatus))
{
    typedef bool (*policy_fn_t)(void (*abortfunc)(enum mcheck_status mstatus));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mcheck_pedantic_policy");
    if (policy && !policy(abortfunc))
        abort();
    return mcheck_pedantic(abortfunc);
}

#include <stdlib.h>
#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int memalign_wrapper(void **memptr, size_t alignment, size_t size)
{
    typedef bool (*policy_fn_t)(void **, size_t, size_t);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memalign_policy");
    if (policy && !policy(memptr, alignment, size))
        abort();

    // Modern replacement for memalign
    return posix_memalign(memptr, alignment, size);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *memccpy_wrapper(void *dest, const void *src, int c, size_t n)
{
    typedef bool (*policy_fn_t)(void *dest, const void *src, int c, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memccpy_policy");
    if (policy && !policy(dest, src, c, n))
        abort();
    return memccpy(dest, src, c, n);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const void *memrchr_wrapper(const void *s, int c, size_t n)
{
    typedef bool (*policy_fn_t)(const void *, int, size_t);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "memrchr_policy");
    if (policy && !policy(s, c, n))
        abort();

    return memrchr(s, c, n);
}


#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int memcmp_wrapper(const void *s1, const void *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const void *s1, const void *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memcmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return memcmp(s1, s2, n);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *memcpy_wrapper(void *dest, const void *src, size_t n)
{
    typedef bool (*policy_fn_t)(void *dest, const void *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memcpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return memcpy(dest, src, n);
}

#include <sys/mman.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int memfd_create_wrapper(const char *name, unsigned int flags)
{
    typedef bool (*policy_fn_t)(const char *name, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memfd_create_policy");
    if (policy && !policy(name, flags))
        abort();
    return memfd_create(name, flags);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *memfrob_wrapper(void *s, size_t n)
{
    typedef bool (*policy_fn_t)(void *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memfrob_policy");
    if (policy && !policy(s, n))
        abort();
    return memfrob(s, n);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *memmem_wrapper(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    typedef bool (*policy_fn_t)(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memmem_policy");
    if (policy && !policy(haystack, haystacklen, needle, needlelen))
        abort();
    return memmem(haystack, haystacklen, needle, needlelen);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *memmove_wrapper(void *dest, const void *src, size_t n)
{
    typedef bool (*policy_fn_t)(void *dest, const void *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memmove_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return memmove(dest, src, n);
}

#include <string.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *mempcpy_wrapper(void *dest, const void *src, size_t n)
{
    typedef bool (*policy_fn_t)(void *dest, const void *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mempcpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return mempcpy(dest, src, n);
}

// #include <string.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void *memrchr_wrapper(const void *s, int c, size_t n)
// {
//     typedef bool (*policy_fn_t)(const void *s, int c, size_t n);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memrchr_policy");
//     if (policy && !policy(s, c, n))
//         abort();
//     return memrchr(s, c, n);
// }

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *memset_wrapper(void *s, int c, size_t n)
{
    typedef bool (*policy_fn_t)(void *s, int c, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "memset_policy");
    if (policy && !policy(s, c, n))
        abort();
    return memset(s, c, n);
}

#include <unistd.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mincore_wrapper(void *addr, size_t length, unsigned char *vec)
{
    typedef bool (*policy_fn_t)(void *addr, size_t length, unsigned char *vec);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mincore_policy");
    if (policy && !policy(addr, length, vec))
        abort();
    return mincore(addr, length, vec);
}

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkdir_wrapper(const char *pathname, mode_t mode)
{
    //wakka printffrom mkdir\n");
    typedef bool (*policy_fn_t)(const char *pathname, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mkdir_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return mkdir(pathname, mode);
}

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkdirat_wrapper(int dirfd, const char *pathname, mode_t mode)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mkdirat_policy");
    if (policy && !policy(dirfd, pathname, mode))
        abort();
    return mkdirat(dirfd, pathname, mode);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *mkdtemp_wrapper(char *tmpl)
{
    typedef bool (*policy_fn_t)(char *tmpl);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "mkdtemp_policy");
    if (policy && !policy(tmpl))
        abort();

    return mkdtemp(tmpl);
}


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkfifo_wrapper(const char *pathname, mode_t mode)
{
    typedef bool (*policy_fn_t)(const char *pathname, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mkfifo_policy");
    if (policy && !policy(pathname, mode))
        abort();
    return mkfifo(pathname, mode);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkfifoat_wrapper(int dirfd, const char *pathname, mode_t mode)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mkfifoat_policy");
    if (policy && !policy(dirfd, pathname, mode))
        abort();
    return mkfifoat(dirfd, pathname, mode);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mknod_wrapper(const char *pathname, mode_t mode, dev_t dev)
{
    typedef bool (*policy_fn_t)(const char *pathname, mode_t mode, dev_t dev);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mknod_policy");
    if (policy && !policy(pathname, mode, dev))
        abort();
    return mknod(pathname, mode, dev);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mknodat_wrapper(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, mode_t mode, dev_t dev);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mknodat_policy");
    if (policy && !policy(dirfd, pathname, mode, dev))
        abort();
    return mknodat(dirfd, pathname, mode, dev);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkostemp_wrapper(char *tmpl, int flags)
{
    typedef bool (*policy_fn_t)(char *tmpl, int flags);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "mkostemp_policy");

    if (policy && !policy(tmpl, flags))
        abort();

    return mkostemp(tmpl, flags);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkostemps_wrapper(char *tmpl, int suffixlen, int flags)
{
    typedef bool (*policy_fn_t)(char *tmpl, int suffixlen, int flags);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "mkostemps_policy");

    if (policy && !policy(tmpl, suffixlen, flags))
        abort();

    return mkostemps(tmpl, suffixlen, flags);
}


#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>
int mkstemp_wrapper(char *tmpl)
{
    //wakka printffrom mkstemp\n");

    typedef bool (*policy_fn_t)(char *tmpl);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "mkstemp_policy");

    if (policy && !policy(tmpl))
        abort();

    return mkstemp(tmpl);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mkstemps_wrapper(char *tmpl, int suffixlen)
{
    typedef bool (*policy_fn_t)(char *tmpl, int suffixlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mkstemps_policy");
    if (policy && !policy(tmpl, suffixlen))
        abort();
    return mkstemps(tmpl, suffixlen);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *mktemp_wrapper(char *tmpl)
{
    typedef bool (*policy_fn_t)(char *tmpl);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mktemp_policy");
    if (policy && !policy(tmpl))
        abort();
    return mktemp(tmpl);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

time_t mktime_wrapper(struct tm *tm)
{
    typedef bool (*policy_fn_t)(struct tm *tm);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mktime_policy");
    if (policy && !policy(tm))
        abort();
    return mktime(tm);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mlock_wrapper(const void *addr, size_t len)
{
    typedef bool (*policy_fn_t)(const void *addr, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mlock_policy");
    if (policy && !policy(addr, len))
        abort();
    return mlock(addr, len);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mlock2_wrapper(const void *addr, size_t len, int flags)
{
    typedef bool (*policy_fn_t)(const void *addr, size_t len, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mlock2_policy");
    if (policy && !policy(addr, len, flags))
        abort();
    return mlock2(addr, len, flags);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mlockall_wrapper(int flags)
{
    //wakka printfFrom mlockall\n");
    //wakka printfflags : %d\n", flags);
    typedef bool (*policy_fn_t)(int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mlockall_policy");
    if (policy && !policy(flags))
        abort();
    return mlockall(flags);
}

#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *mmap_wrapper(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    FILE *log = fopen("mmap.txt", "a");
    if (log != NULL)
    {
        char buf[PATH_MAX];
        if (fd >= 0) // valid file descriptor
        {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            ssize_t len = readlink(path, buf, sizeof(buf) - 1);
            if (len != -1)
            {
                buf[len] = '\0';
            }
            else
            {
                snprintf(buf, sizeof(buf), "unknown");
            }
        }
        else
        {
            snprintf(buf, sizeof(buf), "N/A");
        }

        fprintf(log,
                "from mmap: addr=%p, length=%zu, prot=0x%x, flags=0x%x, fd=%d (%s), offset=%ld\n",
                addr, length, prot, flags, fd, buf, (long)offset);

        fclose(log);
    }
    typedef bool (*policy_fn_t)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mmap_policy");
    if (policy && !policy(addr, length, prot, flags, fd, offset))
        abort();
    return mmap(addr, length, prot, flags, fd, offset);
}

#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *mmap64_wrapper(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    typedef bool (*policy_fn_t)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mmap64_policy");
    if (policy && !policy(addr, length, prot, flags, fd, offset))
        abort();
    return mmap64(addr, length, prot, flags, fd, offset);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double modf_wrapper(double x, double *iptr)
{
    typedef bool (*policy_fn_t)(double x, double *iptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "modf_policy");
    if (policy && !policy(x, iptr))
        abort();
    return modf(x, iptr);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

float modff_wrapper(float x, float *iptr)
{
    typedef bool (*policy_fn_t)(float x, float *iptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "modff_policy");
    if (policy && !policy(x, iptr))
        abort();
    return modff(x, iptr);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long double modfl_wrapper(long double x, long double *iptr)
{
    typedef bool (*policy_fn_t)(long double x, long double *iptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "modfl_policy");
    if (policy && !policy(x, iptr))
        abort();
    return modfl(x, iptr);
}

// #include <sys/types.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int modify_ldt_wrapper(int func, void *ptr, unsigned long bytecount)
// {
//     typedef bool (*policy_fn_t)(int func, void *ptr, unsigned long bytecount);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "modify_ldt_policy");
//     if (policy && !policy(func, ptr, bytecount))
//         abort();
//     return modify_ldt(func, ptr, bytecount);
// }

#include <sys/mount.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mount_wrapper(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data)
{
    typedef bool (*policy_fn_t)(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mount_policy");
    if (policy && !policy(source, target, filesystemtype, mountflags, data))
        abort();
    return mount(source, target, filesystemtype, mountflags, data);
}

#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>
#include <mcheck.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

enum mcheck_status mprobe_wrapper(void *ptr)
{
    typedef bool (*policy_fn_t)(void *ptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mprobe_policy");
    if (policy && !policy(ptr))
        abort();
    return mprobe(ptr);
}

#include <sys/mman.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mprotect_wrapper(void *addr, size_t len, int prot)
{
    //wakka printffrom mprotect\n");
    typedef bool (*policy_fn_t)(void *addr, size_t len, int prot);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mprotect_policy");
    if (policy && !policy(addr, len, prot))
        abort();
    return mprotect(addr, len, prot);
}

#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_close_wrapper(mqd_t mqdes)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_close_policy");
    if (policy && !policy(mqdes))
        abort();
    return mq_close(mqdes);
}

#include <mqueue.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_getattr_wrapper(mqd_t mqdes, struct mq_attr *attr)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, struct mq_attr *attr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_getattr_policy");
    if (policy && !policy(mqdes, attr))
        abort();
    return mq_getattr(mqdes, attr);
}

#include <mqueue.h>
#include <pthread.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_notify_wrapper(mqd_t mqdes, const struct sigevent *sevp)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, const struct sigevent *sevp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_notify_policy");
    if (policy && !policy(mqdes, sevp))
        abort();
    return mq_notify(mqdes, sevp);
}

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

mqd_t mq_open_wrapper(const char *name, int oflag)
{
    typedef bool (*policy_fn_t)(const char *name, int oflag);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_open_policy");
    if (policy && !policy(name, oflag))
        abort();
    return mq_open(name, oflag);
}

#include <mqueue.h>
#include <time.h>
#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t mq_receive_wrapper(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_receive_policy");
    if (policy && !policy(mqdes, msg_ptr, msg_len, msg_prio))
        abort();
    return mq_receive(mqdes, msg_ptr, msg_len, msg_prio);
}

#include <mqueue.h>
#include <time.h>
#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_send_wrapper(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_send_policy");
    if (policy && !policy(mqdes, msg_ptr, msg_len, msg_prio))
        abort();
    return mq_send(mqdes, msg_ptr, msg_len, msg_prio);
}

#include <mqueue.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_setattr_wrapper(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_setattr_policy");
    if (policy && !policy(mqdes, newattr, oldattr))
        abort();
    return mq_setattr(mqdes, newattr, oldattr);
}

#include <mqueue.h>
#include <time.h>
#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t mq_timedreceive_wrapper(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_timedreceive_policy");
    if (policy && !policy(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout))
        abort();
    return mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}

#include <mqueue.h>
#include <time.h>
#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_timedsend_wrapper(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout)
{
    typedef bool (*policy_fn_t)(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_timedsend_policy");
    if (policy && !policy(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout))
        abort();
    return mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}

#include <mqueue.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mq_unlink_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mq_unlink_policy");
    if (policy && !policy(name))
        abort();
    return mq_unlink(name);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long mrand48_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mrand48_policy");
    if (policy && !policy())
        abort();
    return mrand48();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int mrand48_r_wrapper(struct drand48_data *buffer, long *result)
{
    typedef bool (*policy_fn_t)(struct drand48_data *buffer, long *result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mrand48_r_policy");
    if (policy && !policy(buffer, result))
        abort();
    return mrand48_r(buffer, result);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *mremap_wrapper(void *old_address, size_t old_size, size_t new_size, int flags, ...)
{
    va_list args;
    va_start(args, flags);

    void *var_argv[1];
    var_argv[0] = va_arg(args, void *);

    typedef bool (*policy_fn_t)(void *, size_t, size_t, long[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mremap_policy");

    if (policy && !policy(old_address, old_size, new_size, (long *)var_argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return mremap(old_address, old_size, new_size, flags, var_argv[0]);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int msgctl_wrapper(int msqid, int cmd, struct msqid_ds *buf)
{
    typedef bool (*policy_fn_t)(int msqid, int cmd, struct msqid_ds *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "msgctl_policy");
    if (policy && !policy(msqid, cmd, buf))
        abort();
    return msgctl(msqid, cmd, buf);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int msgget_wrapper(key_t key, int msgflg)
{
    typedef bool (*policy_fn_t)(key_t key, int msgflg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "msgget_policy");
    if (policy && !policy(key, msgflg))
        abort();
    return msgget(key, msgflg);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t msgrcv_wrapper(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    typedef bool (*policy_fn_t)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "msgrcv_policy");
    if (policy && !policy(msqid, msgp, msgsz, msgtyp, msgflg))
        abort();
    return msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int msgsnd_wrapper(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
    typedef bool (*policy_fn_t)(int msqid, const void *msgp, size_t msgsz, int msgflg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "msgsnd_policy");
    if (policy && !policy(msqid, msgp, msgsz, msgflg))
        abort();
    return msgsnd(msqid, msgp, msgsz, msgflg);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int msync_wrapper(void *addr, size_t length, int flags)
{
    typedef bool (*policy_fn_t)(void *addr, size_t length, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "msync_policy");
    if (policy && !policy(addr, length, flags))
        abort();
    return msync(addr, length, flags);
}

#include <mcheck.h>
#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void mtrace_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "mtrace_policy");
    if (policy && !policy())
        abort();
    mtrace();
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int munlock_wrapper(const void *addr, size_t len)
{
    typedef bool (*policy_fn_t)(const void *addr, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "munlock_policy");
    if (policy && !policy(addr, len))
        abort();
    return munlock(addr, len);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int munlockall_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "munlockall_policy");
    if (policy && !policy())
        abort();
    return munlockall();
}

#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int munmap_wrapper(void *addr, size_t length)
{
    //wakka printffrom munmap\n");
    typedef bool (*policy_fn_t)(void *addr, size_t length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "munmap_policy");
    if (policy && !policy(addr, length))
        abort();
    return munmap(addr, length);
}

#include <mcheck.h>
#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void muntrace_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "muntrace_policy");
    if (policy && !policy())
        abort();
    muntrace();
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int name_to_handle_at_wrapper(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "name_to_handle_at_policy");
    if (policy && !policy(dirfd, pathname, handle, mount_id, flags))
        abort();
    return name_to_handle_at(dirfd, pathname, handle, mount_id, flags);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int nanosleep_wrapper(const struct timespec *req, struct timespec *rem)
{
    //wakka printffrom nanosleep\n");
    typedef bool (*policy_fn_t)(const struct timespec *req, struct timespec *rem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "nanosleep_policy");
    if (policy && !policy(req, rem))
        abort();
    return nanosleep(req, rem);
}

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

locale_t newlocale_wrapper(int category_mask, const char *locale, locale_t base)
{
    typedef bool (*policy_fn_t)(int category_mask, const char *locale, locale_t base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "newlocale_policy");
    if (policy && !policy(category_mask, locale, base))
        abort();
    return newlocale(category_mask, locale, base);
}

// #include <linux/nfsd/syscall.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// long nfsservctl_wrapper(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp) {
//     typedef bool (*policy_fn_t)(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "nfsservctl_policy");
//     if(policy && !policy(cmd, argp, resp)) abort();
//     return nfsservctl(cmd, argp, resp);
// }

#include <ftw.h>
#include <ftw.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int nftw_wrapper(const char *dirpath, int (*fn)(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf), int nopenfd, int flags)
{
    typedef bool (*policy_fn_t)(const char *dirpath, int (*fn)(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf), int nopenfd, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "nftw_policy");
    if (policy && !policy(dirpath, fn, nopenfd, flags))
        abort();
    return nftw(dirpath, fn, nopenfd, flags);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ngettext_wrapper(const char *msgid, const char *msgid_plural, unsigned long int n)
{
    typedef bool (*policy_fn_t)(const char *msgid, const char *msgid_plural, unsigned long int n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ngettext_policy");
    if (policy && !policy(msgid, msgid_plural, n))
        abort();
    return ngettext(msgid, msgid_plural, n);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int nice_wrapper(int inc)
{
    typedef bool (*policy_fn_t)(int inc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "nice_policy");
    if (policy && !policy(inc))
        abort();
    return nice(inc);
}

#include <langinfo.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *nl_langinfo_wrapper(nl_item item)
{
    typedef bool (*policy_fn_t)(nl_item item);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "nl_langinfo_policy");
    if (policy && !policy(item))
        abort();
    return nl_langinfo(item);
}

#include <langinfo.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *nl_langinfo_l_wrapper(nl_item item, locale_t locale)
{
    typedef bool (*policy_fn_t)(nl_item item, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "nl_langinfo_l_policy");
    if (policy && !policy(item, locale))
        abort();
    return nl_langinfo_l(item, locale);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long nrand48_wrapper(unsigned short xsubi[3])
{
    typedef bool (*policy_fn_t)(unsigned short xsubi[3]);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "nrand48_policy");

    if (policy && !policy(xsubi))
        abort();

    return nrand48(xsubi);
}


#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int nrand48_r_wrapper(unsigned short xsubi[3],
                      struct drand48_data *buffer,
                      long *result)
{
    typedef bool (*policy_fn_t)(unsigned short xsubi[3],
                                struct drand48_data *buffer,
                                long *result);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "nrand48_r_policy");

    if (policy && !policy(xsubi, buffer, result))
        abort();

    return nrand48_r(xsubi, buffer, result);
}

#include <arpa/inet.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uint32_t ntohl_wrapper(uint32_t netlong)
{
    typedef bool (*policy_fn_t)(uint32_t netlong);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ntohl_policy");
    if (policy && !policy(netlong))
        abort();
    return ntohl(netlong);
}

#include <arpa/inet.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uint16_t ntohs_wrapper(uint16_t netshort)
{
    typedef bool (*policy_fn_t)(uint16_t netshort);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ntohs_policy");
    if (policy && !policy(netshort))
        abort();
    return ntohs(netshort);
}

#include <sys/timex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ntp_adjtime_wrapper(struct timex *buf)
{
    typedef bool (*policy_fn_t)(struct timex *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ntp_adjtime_policy");
    if (policy && !policy(buf))
        abort();
    return ntp_adjtime(buf);
}

#include <sys/timex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ntp_gettime_wrapper(struct ntptimeval *ntv)
{
    typedef bool (*policy_fn_t)(struct ntptimeval *ntv);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ntp_gettime_policy");
    if (policy && !policy(ntv))
        abort();
    return ntp_gettime(ntv);
}

#include <sys/timex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ntp_gettimex_wrapper(struct ntptimeval *ntv)
{
    typedef bool (*policy_fn_t)(struct ntptimeval *ntv);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ntp_gettimex_policy");
    if (policy && !policy(ntv))
        abort();
    return ntp_gettimex(ntv);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int on_exit_wrapper(void (*function)(int, void *), void *arg)
{
    typedef bool (*policy_fn_t)(void (*function)(int, void *), void *arg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "on_exit_policy");
    if (policy && !policy(function, arg))
        abort();
    return on_exit(function, arg);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>

int open_wrapper(const char *pathname, int flags, ...)
{

    // open log file
    FILE *log = fopen("open.txt", "a");
    if (log != NULL)
    {
        fprintf(log, "from open: pathname=%s, flags=0x%x\n", pathname, flags);
        fclose(log);
    }
    // policy
    typedef bool (*policy_fn_t)(const char *, int);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "open_policy");
    if (policy && !policy(pathname, flags))
        abort();

    // optional mode_t when O_CREAT or O_TMPFILE is set
    // handle optional mode_t when O_CREAT or O_TMPFILE is set
    mode_t mode = 0;
    int need_mode = (flags & (O_CREAT | O_TMPFILE)) ? 1 : 0;
    if (need_mode)
    {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    // just call libc's open() directly
    if (need_mode)
    {
        return open(pathname, flags, mode);
    }
    else
    {
        return open(pathname, flags);
    }
}

int open64_wrapper(const char *pathname, int flags, ...)
{
    //wakka printfFrom open64\n");
    //wakka printfpath name = %s\n", pathname);
    // policy
    typedef bool (*policy_fn_t)(const char *, int);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "open64_policy");
    if (policy && !policy(pathname, flags))
        abort();

    // optional mode_t when O_CREAT or O_TMPFILE is set
    // handle optional mode_t when O_CREAT or O_TMPFILE is set
    mode_t mode = 0;
    int need_mode = (flags & (O_CREAT | O_TMPFILE)) ? 1 : 0;
    if (need_mode)
    {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    // just call libc's open() directly
    if (need_mode)
    {
        return open64(pathname, flags, mode);
    }
    else
    {
        return open64(pathname, flags);
    }
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int open_by_handle_at_wrapper(int mount_fd, struct file_handle *handle, int flags)
{
    typedef bool (*policy_fn_t)(int mount_fd, struct file_handle *handle, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "open_by_handle_at_policy");
    if (policy && !policy(mount_fd, handle, flags))
        abort();
    return open_by_handle_at(mount_fd, handle, flags);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *open_memstream_wrapper(char **ptr, size_t *sizeloc)
{
    typedef bool (*policy_fn_t)(char **ptr, size_t *sizeloc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "open_memstream_policy");
    if (policy && !policy(ptr, sizeloc))
        abort();
    return open_memstream(ptr, sizeloc);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *open_wmemstream_wrapper(wchar_t **ptr, size_t *sizeloc)
{
    typedef bool (*policy_fn_t)(wchar_t **ptr, size_t *sizeloc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "open_wmemstream_policy");
    if (policy && !policy(ptr, sizeloc))
        abort();
    return open_wmemstream(ptr, sizeloc);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int openat_wrapper(int dirfd, const char *pathname, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "openat_policy");
    if (policy && !policy(dirfd, pathname, flags))
        abort();
    return openat(dirfd, pathname, flags);
}

#include <sys/types.h>
#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

DIR *opendir_wrapper(const char *name)
{
    //wakka printffrom opendir\n");
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "opendir_policy");
    if (policy && !policy(name))
        abort();
    return opendir(name);
}

#include <syslog.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void openlog_wrapper(const char *ident, int option, int facility)
{
    typedef bool (*policy_fn_t)(const char *ident, int option, int facility);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "openlog_policy");
    if (policy && !policy(ident, option, facility))
        abort();
    openlog(ident, option, facility);
}

#include <pty.h>
#include <utmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int openpty_wrapper(int *amaster, int *lave, char *name, const struct termios *termp, const struct winsize *winp)
{
    typedef bool (*policy_fn_t)(int *amaster, int *lave, char *name, const struct termios *termp, const struct winsize *winp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "openpty_policy");
    if (policy && !policy(amaster, lave, name, termp, winp))
        abort();
    return openpty(amaster, lave, name, termp, winp);
}

//// #include <rpc/des_crypt.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void passwd2des_wrapper(char *passwd, char *key)
{
    typedef bool (*policy_fn_t)(char *passwd, char *key);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "passwd2des_policy");
    if (policy && !policy(passwd, key))
        abort();
    passwd2des(passwd, key);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long pathconf_wrapper(int fd, int name)
{
    typedef bool (*policy_fn_t)(int fd, int name);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "pathconf_policy");
    if (policy && !policy(fd, name))
        abort();

    return fpathconf(fd, name);   // <-- FD version
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pause_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pause_policy");
    if (policy && !policy())
        abort();
    return pause();
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pclose_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pclose_policy");
    if (policy && !policy(stream))
        abort();
    return pclose(stream);
}

#include <stdio.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void perror_wrapper(const char *s)
{
    typedef bool (*policy_fn_t)(const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "perror_policy");
    if (policy && !policy(s))
        abort();
    perror(s);
}

#include <sys/personality.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int personality_wrapper(unsigned long persona)
{
    typedef bool (*policy_fn_t)(unsigned long persona);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "personality_policy");
    if (policy && !policy(persona))
        abort();
    return personality(persona);
}

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>

struct fd_pair
{
    int fd[2];
};

struct fd_pair pipe_wrapper()
{
    struct fd_pair fds;

    typedef bool (*policy_fn_t)(int pipefd[2]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pipe_policy");
    if (policy && !policy(fds.fd))
        abort();

    if (pipe(fds.fd) == -1)
    {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    return fds;
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pipe2_wrapper(int pipefd[2], int flags)
{
    typedef bool (*policy_fn_t)(int pipefd[2], int flags);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "pipe2_policy");
    if (policy && !policy(pipefd, flags))
        abort();

    return pipe2(pipefd, flags);
}


// #include <sched.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <sys/wait.h>
// #include <sys/syscall.h>
// #include <sys/mount.h>
// #include <sys/stat.h>
// #include <limits.h>
// #include <sys/mman.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int pivot_root_wrapper(const char *new_root, const char *put_old)
// {
//     typedef bool (*policy_fn_t)(const char *new_root, const char *put_old);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pivot_root_policy");
//     if (policy && !policy(new_root, put_old))
//         abort();
//     return pivot_root(new_root, put_old);
// }

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pkey_alloc_wrapper(unsigned int flags, unsigned int access_rights)
{
    typedef bool (*policy_fn_t)(unsigned int flags, unsigned int access_rights);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pkey_alloc_policy");
    if (policy && !policy(flags, access_rights))
        abort();
    return pkey_alloc(flags, access_rights);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pkey_free_wrapper(int pkey)
{
    typedef bool (*policy_fn_t)(int pkey);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pkey_free_policy");
    if (policy && !policy(pkey))
        abort();
    return pkey_free(pkey);
}

#include <sys/mman.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pkey_mprotect_wrapper(void *addr, size_t len, int prot, int pkey)
{
    typedef bool (*policy_fn_t)(void *addr, size_t len, int prot, int pkey);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pkey_mprotect_policy");
    if (policy && !policy(addr, len, prot, pkey))
        abort();
    return pkey_mprotect(addr, len, prot, pkey);
}

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// struct pmaplist *pmap_getmaps_wrapper(struct sockaddr_in *addr)
// {
//     typedef bool (*policy_fn_t)(struct sockaddr_in *addr);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pmap_getmaps_policy");
//     if (policy && !policy(addr))
//         abort();
//     return pmap_getmaps(addr);
// }

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// unsigned short pmap_getport_wrapper(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, unsigned int protocol)
// {
//     typedef bool (*policy_fn_t)(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, unsigned int protocol);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pmap_getport_policy");
//     if (policy && !policy(addr, prognum, versnum, protocol))
//         abort();
//     return pmap_getport(addr, prognum, versnum, protocol);
// }

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// enum clnt_stat pmap_rmtcall_wrapper(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out, struct timeval tout, unsigned long *portp)
// {
//     typedef bool (*policy_fn_t)(struct sockaddr_in *addr, unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out, struct timeval tout, unsigned long *portp);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pmap_rmtcall_policy");
//     if (policy && !policy(addr, prognum, versnum, procnum, inproc, in, outproc, out, tout, portp))
//         abort();
//     return pmap_rmtcall(addr, prognum, versnum, procnum, inproc, in, outproc, out, tout, portp);
// }

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// bool_t pmap_set_wrapper(unsigned long prognum, unsigned long versnum, unsigned int protocol, unsigned short port)
// {
//     typedef bool (*policy_fn_t)(unsigned long prognum, unsigned long versnum, unsigned int protocol, unsigned short port);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pmap_set_policy");
//     if (policy && !policy(prognum, versnum, protocol, port))
//         abort();
//     return pmap_set(prognum, versnum, protocol, port);
// }

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// bool_t pmap_unset_wrapper(unsigned long prognum, unsigned long versnum)
// {
//     typedef bool (*policy_fn_t)(unsigned long prognum, unsigned long versnum);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pmap_unset_policy");
//     if (policy && !policy(prognum, versnum))
//         abort();
//     return pmap_unset(prognum, versnum);
// }

#include <poll.h>
#include <signal.h>
#include <poll.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int poll_wrapper(struct pollfd *fds, nfds_t nfds, int timeout)
{
    //wakka printffrom poll\n");
    // Print the number of FDs
    fprintf(stdout, "[policy] poll() called with nfds=%lu, timeout=%d\n",
            (unsigned long)nfds, timeout);

    // Iterate through all FDs
    for (nfds_t i = 0; i < nfds; i++)
    {
        char path[64], target[256];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fds[i].fd);

        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len != -1)
        {
            target[len] = '\0';
        }
        else
        {
            strncpy(target, "unknown", sizeof(target));
        }

        fprintf(stdout, "   fd=%d -> %s (events=0x%x)\n",
                fds[i].fd, target, fds[i].events);
    }
    typedef bool (*policy_fn_t)(struct pollfd *fds, nfds_t nfds, int timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "poll_policy");
    if (policy && !policy(fds, nfds, timeout))
        abort();
    return poll(fds, nfds, timeout);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *popen_wrapper(const char *command, const char *type)
{
    typedef bool (*policy_fn_t)(const char *command, const char *type);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "popen_policy");
    if (policy && !policy(command, type))
        abort();
    return popen(command, type);
}

#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_fadvise_wrapper(int fd, off_t offset, off_t len, int advice)
{
    typedef bool (*policy_fn_t)(int fd, off_t offset, off_t len, int advice);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_fadvise_policy");
    if (policy && !policy(fd, offset, len, advice))
        abort();
    return posix_fadvise(fd, offset, len, advice);
}

#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_fallocate_wrapper(int fd, off_t offset, off_t len)
{
    typedef bool (*policy_fn_t)(int fd, off_t offset, off_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_fallocate_policy");
    if (policy && !policy(fd, offset, len))
        abort();
    return posix_fallocate(fd, offset, len);
}

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_madvise_wrapper(void *addr, size_t len, int advice)
{
    typedef bool (*policy_fn_t)(void *addr, size_t len, int advice);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_madvise_policy");
    if (policy && !policy(addr, len, advice))
        abort();
    return posix_madvise(addr, len, advice);
}

#include <stdlib.h>
#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_memalign_wrapper(void **memptr, size_t alignment, size_t size)
{
    typedef bool (*policy_fn_t)(void **memptr, size_t alignment, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_memalign_policy");
    if (policy && !policy(memptr, alignment, size))
        abort();
    return posix_memalign(memptr, alignment, size);
}

#include <stdlib.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_openpt_wrapper(int flags)
{
    typedef bool (*policy_fn_t)(int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_openpt_policy");
    if (policy && !policy(flags))
        abort();
    return posix_openpt(flags);
}

#include <spawn.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_spawn_wrapper(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
    typedef bool (*policy_fn_t)(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_spawn_policy");
    if (policy && !policy(pid, path, file_actions, attrp, argv, envp))
        abort();
    return posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

#include <spawn.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <wait.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int posix_spawnp_wrapper(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
    typedef bool (*policy_fn_t)(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "posix_spawnp_policy");
    if (policy && !policy(pid, file, file_actions, attrp, argv, envp))
        abort();
    return posix_spawnp(pid, file, file_actions, attrp, argv, envp);
}

#include <poll.h>
#include <signal.h>
#include <poll.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ppoll_wrapper(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    typedef bool (*policy_fn_t)(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ppoll_policy");
    if (policy && !policy(fds, nfds, tmo_p, sigmask))
        abort();
    return ppoll(fds, nfds, tmo_p, sigmask);
}

#include <sys/prctl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int prctl_wrapper(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    //wakka printfFrom prctl\n");
    typedef bool (*policy_fn_t)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "prctl_policy");
    if (policy && !policy(option, arg2, arg3, arg4, arg5))
        abort();
    return prctl(option, arg2, arg3, arg4, arg5);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t pread_wrapper(int fd, void *buf, size_t count, off_t offset)
{
    typedef bool (*policy_fn_t)(int fd, void *buf, size_t count, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pread_policy");
    if (policy && !policy(fd, buf, count, offset))
        abort();
    return pread(fd, buf, count, offset);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t pread64_wrapper(int fd, void *buf, size_t count, off_t offset)
{
    typedef bool (*policy_fn_t)(int fd, void *buf, size_t count, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pread64_policy");
    if (policy && !policy(fd, buf, count, offset))
        abort();
    return pread64(fd, buf, count, offset);
}

#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t preadv_wrapper(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, int iovcnt, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "preadv_policy");
    if (policy && !policy(fd, iov, iovcnt, offset))
        abort();
    return preadv(fd, iov, iovcnt, offset);
}

#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t preadv2_wrapper(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "preadv2_policy");
    if (policy && !policy(fd, iov, iovcnt, offset, flags))
        abort();
    return preadv2(fd, iov, iovcnt, offset, flags);
}

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int printf_wrapper(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
    {
        var_argv[vi++] = next;
    }
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(const char *format, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "printf_policy");
    if (policy && !policy(format, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vprintf(format, args);

    va_end(args);
    return ret;
}

#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int prlimit_wrapper(pid_t pid, int resource,
                    const struct rlimit *new_limit,
                    struct rlimit *old_limit)
{
    typedef bool (*policy_fn_t)(pid_t, int,
                                const struct rlimit *,
                                struct rlimit *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "prlimit_policy");

    if (policy && !policy(pid, resource, new_limit, old_limit))
        abort();

    return prlimit(pid,
                   static_cast<__rlimit_resource>(resource),
                   new_limit,
                   old_limit);
}


#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int prlimit64_wrapper(pid_t pid, int resource,
                      const struct rlimit *new_limit,
                      struct rlimit *old_limit)
{
    typedef bool (*policy_fn_t)(pid_t, int,
                                const struct rlimit *,
                                struct rlimit *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "prlimit64_policy");

    if (policy && !policy(pid, resource, new_limit, old_limit))
        abort();

    return prlimit(pid,
                   static_cast<__rlimit_resource>(resource),
                   new_limit,
                   old_limit);
}


#include <sys/uio.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t process_vm_readv_wrapper(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
    typedef bool (*policy_fn_t)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "process_vm_readv_policy");
    if (policy && !policy(pid, local_iov, liovcnt, remote_iov, riovcnt, flags))
        abort();
    return process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

#include <sys/uio.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t process_vm_writev_wrapper(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
    typedef bool (*policy_fn_t)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "process_vm_writev_policy");
    if (policy && !policy(pid, local_iov, liovcnt, remote_iov, riovcnt, flags))
        abort();
    return process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pselect_wrapper(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask)
{
    typedef bool (*policy_fn_t)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pselect_policy");
    if (policy && !policy(nfds, readfds, writefds, exceptfds, timeout, sigmask))
        abort();
    return pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void psiginfo_wrapper(const siginfo_t *pinfo, const char *s)
{
    typedef bool (*policy_fn_t)(const siginfo_t *pinfo, const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "psiginfo_policy");
    if (policy && !policy(pinfo, s))
        abort();
    psiginfo(pinfo, s);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void psignal_wrapper(int sig, const char *s)
{
    typedef bool (*policy_fn_t)(int sig, const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "psignal_policy");
    if (policy && !policy(sig, s))
        abort();
    psignal(sig, s);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_destroy_wrapper(pthread_attr_t *attr)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_destroy_policy");
    if (policy && !policy(attr))
        abort();
    return pthread_attr_destroy(attr);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getaffinity_np_wrapper(const pthread_attr_t *attr, size_t cpusetsize, cpu_set_t *cpuset)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, size_t cpusetsize, cpu_set_t *cpuset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getaffinity_np_policy");
    if (policy && !policy(attr, cpusetsize, cpuset))
        abort();
    return pthread_attr_getaffinity_np(attr, cpusetsize, cpuset);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getdetachstate_wrapper(const pthread_attr_t *attr, int *detachstate)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, int *detachstate);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getdetachstate_policy");
    if (policy && !policy(attr, detachstate))
        abort();
    return pthread_attr_getdetachstate(attr, detachstate);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getguardsize_wrapper(const pthread_attr_t *attr, size_t *guardsize)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, size_t *guardsize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getguardsize_policy");
    if (policy && !policy(attr, guardsize))
        abort();
    return pthread_attr_getguardsize(attr, guardsize);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getinheritsched_wrapper(const pthread_attr_t *attr, int *inheritsched)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, int *inheritsched);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getinheritsched_policy");
    if (policy && !policy(attr, inheritsched))
        abort();
    return pthread_attr_getinheritsched(attr, inheritsched);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getschedparam_wrapper(const pthread_attr_t *attr, struct sched_param *param)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, struct sched_param *param);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getschedparam_policy");
    if (policy && !policy(attr, param))
        abort();
    return pthread_attr_getschedparam(attr, param);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getschedpolicy_wrapper(const pthread_attr_t *attr, int *policy)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, int *policy);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getschedpolicy_policy");
    if (policy_fn && !policy_fn(attr, policy))
        abort();
    return pthread_attr_getschedpolicy(attr, policy);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getscope_wrapper(const pthread_attr_t *attr, int *scope)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, int *scope);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getscope_policy");
    if (policy && !policy(attr, scope))
        abort();
    return pthread_attr_getscope(attr, scope);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getsigmask_np_wrapper(const pthread_attr_t *attr, sigset_t *sigmask)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, sigset_t *sigmask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getsigmask_np_policy");
    if (policy && !policy(attr, sigmask))
        abort();
    return pthread_attr_getsigmask_np(attr, sigmask);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getstack_wrapper(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getstack_policy");
    if (policy && !policy(attr, stackaddr, stacksize))
        abort();
    return pthread_attr_getstack(attr, stackaddr, stacksize);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getstackaddr_wrapper(const pthread_attr_t *attr, void **stackaddr)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, void **stackaddr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getstackaddr_policy");
    if (policy && !policy(attr, stackaddr))
        abort();
    return pthread_attr_getstackaddr(attr, stackaddr);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_getstacksize_wrapper(const pthread_attr_t *attr, size_t *stacksize)
{
    typedef bool (*policy_fn_t)(const pthread_attr_t *attr, size_t *stacksize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_getstacksize_policy");
    if (policy && !policy(attr, stacksize))
        abort();
    return pthread_attr_getstacksize(attr, stacksize);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_init_wrapper(pthread_attr_t *attr)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_init_policy");
    if (policy && !policy(attr))
        abort();
    return pthread_attr_init(attr);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setaffinity_np_wrapper(pthread_attr_t *attr, size_t cpusetsize, const cpu_set_t *cpuset)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, size_t cpusetsize, const cpu_set_t *cpuset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setaffinity_np_policy");
    if (policy && !policy(attr, cpusetsize, cpuset))
        abort();
    return pthread_attr_setaffinity_np(attr, cpusetsize, cpuset);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setdetachstate_wrapper(pthread_attr_t *attr, int detachstate)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, int detachstate);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setdetachstate_policy");
    if (policy && !policy(attr, detachstate))
        abort();
    return pthread_attr_setdetachstate(attr, detachstate);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setguardsize_wrapper(pthread_attr_t *attr, size_t guardsize)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, size_t guardsize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setguardsize_policy");
    if (policy && !policy(attr, guardsize))
        abort();
    return pthread_attr_setguardsize(attr, guardsize);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setinheritsched_wrapper(pthread_attr_t *attr, int inheritsched)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, int inheritsched);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setinheritsched_policy");
    if (policy && !policy(attr, inheritsched))
        abort();
    return pthread_attr_setinheritsched(attr, inheritsched);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setschedparam_wrapper(pthread_attr_t *attr, const struct sched_param *param)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, const struct sched_param *param);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setschedparam_policy");
    if (policy && !policy(attr, param))
        abort();
    return pthread_attr_setschedparam(attr, param);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setschedpolicy_wrapper(pthread_attr_t *attr, int policy)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, int policy);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setschedpolicy_policy");
    if (policy_fn && !policy_fn(attr, policy))
        abort();
    return pthread_attr_setschedpolicy(attr, policy);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setscope_wrapper(pthread_attr_t *attr, int scope)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, int scope);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setscope_policy");
    if (policy && !policy(attr, scope))
        abort();
    return pthread_attr_setscope(attr, scope);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setsigmask_np_wrapper(pthread_attr_t *attr, const sigset_t *sigmask)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, const sigset_t *sigmask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setsigmask_np_policy");
    if (policy && !policy(attr, sigmask))
        abort();
    return pthread_attr_setsigmask_np(attr, sigmask);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setstack_wrapper(pthread_attr_t *attr, void *stackaddr, size_t stacksize)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, void *stackaddr, size_t stacksize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setstack_policy");
    if (policy && !policy(attr, stackaddr, stacksize))
        abort();
    return pthread_attr_setstack(attr, stackaddr, stacksize);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setstackaddr_wrapper(pthread_attr_t *attr, void *stackaddr)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, void *stackaddr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setstackaddr_policy");
    if (policy && !policy(attr, stackaddr))
        abort();
    return pthread_attr_setstackaddr(attr, stackaddr);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_attr_setstacksize_wrapper(pthread_attr_t *attr, size_t stacksize)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr, size_t stacksize);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_attr_setstacksize_policy");
    if (policy && !policy(attr, stacksize))
        abort();
    return pthread_attr_setstacksize(attr, stacksize);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_cancel_wrapper(pthread_t thread)
{
    typedef bool (*policy_fn_t)(pthread_t thread);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_cancel_policy");
    if (policy && !policy(thread))
        abort();
    return pthread_cancel(thread);
}

#include <pthread.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_create_wrapper(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    typedef bool (*policy_fn_t)(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_create_policy");
    if (policy && !policy(thread, attr, start_routine, arg))
        abort();
    return pthread_create(thread, attr, start_routine, arg);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_detach_wrapper(pthread_t thread)
{
    typedef bool (*policy_fn_t)(pthread_t thread);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_detach_policy");
    if (policy && !policy(thread))
        abort();
    return pthread_detach(thread);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_equal_wrapper(pthread_t t1, pthread_t t2)
{
    typedef bool (*policy_fn_t)(pthread_t t1, pthread_t t2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_equal_policy");
    if (policy && !policy(t1, t2))
        abort();
    return pthread_equal(t1, t2);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void pthread_exit_wrapper(void *retval)
{
    typedef bool (*policy_fn_t)(void *retval);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_exit_policy");
    if (policy && !policy(retval))
        abort();
    pthread_exit(retval);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getaffinity_np_wrapper(pthread_t thread, size_t cpusetsize, cpu_set_t *cpuset)
{
    typedef bool (*policy_fn_t)(pthread_t thread, size_t cpusetsize, cpu_set_t *cpuset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getaffinity_np_policy");
    if (policy && !policy(thread, cpusetsize, cpuset))
        abort();
    return pthread_getaffinity_np(thread, cpusetsize, cpuset);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getattr_default_np_wrapper(pthread_attr_t *attr)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getattr_default_np_policy");
    if (policy && !policy(attr))
        abort();
    return pthread_getattr_default_np(attr);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getattr_np_wrapper(pthread_t thread, pthread_attr_t *attr)
{
    typedef bool (*policy_fn_t)(pthread_t thread, pthread_attr_t *attr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getattr_np_policy");
    if (policy && !policy(thread, attr))
        abort();
    return pthread_getattr_np(thread, attr);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getconcurrency_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getconcurrency_policy");
    if (policy && !policy())
        abort();
    return pthread_getconcurrency();
}

#include <pthread.h>
#include <time.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getcpuclockid_wrapper(pthread_t thread, clockid_t *clockid)
{
    typedef bool (*policy_fn_t)(pthread_t thread, clockid_t *clockid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getcpuclockid_policy");
    if (policy && !policy(thread, clockid))
        abort();
    return pthread_getcpuclockid(thread, clockid);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getname_np_wrapper(pthread_t thread, char *name, size_t len)
{
    typedef bool (*policy_fn_t)(pthread_t thread, char *name, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getname_np_policy");
    if (policy && !policy(thread, name, len))
        abort();
    return pthread_getname_np(thread, name, len);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_getschedparam_wrapper(pthread_t thread, int *policy, struct sched_param *param)
{
    typedef bool (*policy_fn_t)(pthread_t thread, int *policy, struct sched_param *param);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_getschedparam_policy");
    if (policy_fn && !policy_fn(thread, policy, param))
        abort();
    return pthread_getschedparam(thread, policy, param);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_join_wrapper(pthread_t thread, void **retval)
{
    typedef bool (*policy_fn_t)(pthread_t thread, void **retval);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_join_policy");
    if (policy && !policy(thread, retval))
        abort();
    return pthread_join(thread, retval);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_kill_wrapper(pthread_t thread, int sig)
{
    typedef bool (*policy_fn_t)(pthread_t thread, int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_kill_policy");
    if (policy && !policy(thread, sig))
        abort();
    return pthread_kill(thread, sig);
}

// #include <pthread.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void pthread_kill_other_threads_np_wrapper(void)
// {
//     typedef bool (*policy_fn_t)(void);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_kill_other_threads_np_policy");
//     if (policy && !policy())
//         abort();
//     pthread_kill_other_threads_np();
// }

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutex_consistent_wrapper(pthread_mutex_t *mutex)
{
    typedef bool (*policy_fn_t)(pthread_mutex_t *mutex);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutex_consistent_policy");
    if (policy && !policy(mutex))
        abort();
    return pthread_mutex_consistent(mutex);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutex_consistent_np_wrapper(pthread_mutex_t *mutex)
{
    typedef bool (*policy_fn_t)(pthread_mutex_t *mutex);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutex_consistent_np_policy");
    if (policy && !policy(mutex))
        abort();
    return pthread_mutex_consistent_np(mutex);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutexattr_getpshared_wrapper(const pthread_mutexattr_t *attr, int *pshared)
{
    typedef bool (*policy_fn_t)(const pthread_mutexattr_t *attr, int *pshared);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutexattr_getpshared_policy");
    if (policy && !policy(attr, pshared))
        abort();
    return pthread_mutexattr_getpshared(attr, pshared);
}

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutexattr_getrobust_wrapper(const pthread_mutexattr_t *attr, int *robustness)
{
    typedef bool (*policy_fn_t)(const pthread_mutexattr_t *attr, int *robustness);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutexattr_getrobust_policy");
    if (policy && !policy(attr, robustness))
        abort();
    return pthread_mutexattr_getrobust(attr, robustness);
}

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutexattr_getrobust_np_wrapper(pthread_mutexattr_t *attr,
                                           int *robustness)
{
    typedef bool (*policy_fn_t)(pthread_mutexattr_t *, int *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT,
                           "pthread_mutexattr_getrobust_np_policy");

    if (policy && !policy(attr, robustness))
        abort();

    return pthread_mutexattr_getrobust_np(attr, robustness);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutexattr_setpshared_wrapper(pthread_mutexattr_t *attr, int pshared)
{
    typedef bool (*policy_fn_t)(pthread_mutexattr_t *attr, int pshared);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutexattr_setpshared_policy");
    if (policy && !policy(attr, pshared))
        abort();
    return pthread_mutexattr_setpshared(attr, pshared);
}

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutexattr_setrobust_wrapper(pthread_mutexattr_t *attr, int robustness)
{
    typedef bool (*policy_fn_t)(const pthread_mutexattr_t *attr, int robustness);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutexattr_setrobust_policy");
    if (policy && !policy(attr, robustness))
        abort();
    return pthread_mutexattr_setrobust(attr, robustness);
}

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_mutexattr_setrobust_np_wrapper(pthread_mutexattr_t *attr, int robustness)
{
    typedef bool (*policy_fn_t)(const pthread_mutexattr_t *attr, int robustness);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_mutexattr_setrobust_np_policy");
    if (policy && !policy(attr, robustness))
        abort();
    return pthread_mutexattr_setrobust_np(attr, robustness);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_rwlockattr_getkind_np_wrapper(const pthread_rwlockattr_t *attr, int *pref)
{
    typedef bool (*policy_fn_t)(const pthread_rwlockattr_t *attr, int *pref);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_rwlockattr_getkind_np_policy");
    if (policy && !policy(attr, pref))
        abort();
    return pthread_rwlockattr_getkind_np(attr, pref);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_rwlockattr_setkind_np_wrapper(pthread_rwlockattr_t *attr, int pref)
{
    typedef bool (*policy_fn_t)(pthread_rwlockattr_t *attr, int pref);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_rwlockattr_setkind_np_policy");
    if (policy && !policy(attr, pref))
        abort();
    return pthread_rwlockattr_setkind_np(attr, pref);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pthread_t pthread_self_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_self_policy");
    if (policy && !policy())
        abort();
    return pthread_self();
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setaffinity_np_wrapper(pthread_t thread, size_t cpusetsize, const cpu_set_t *cpuset)
{
    typedef bool (*policy_fn_t)(pthread_t thread, size_t cpusetsize, const cpu_set_t *cpuset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setaffinity_np_policy");
    if (policy && !policy(thread, cpusetsize, cpuset))
        abort();
    return pthread_setaffinity_np(thread, cpusetsize, cpuset);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setattr_default_np_wrapper(pthread_attr_t *attr)
{
    typedef bool (*policy_fn_t)(pthread_attr_t *attr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setattr_default_np_policy");
    if (policy && !policy(attr))
        abort();
    return pthread_setattr_default_np(attr);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setcancelstate_wrapper(int state, int *oldstate)
{
    typedef bool (*policy_fn_t)(int state, int *oldstate);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setcancelstate_policy");
    if (policy && !policy(state, oldstate))
        abort();
    return pthread_setcancelstate(state, oldstate);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setcanceltype_wrapper(int type, int *oldtype)
{
    typedef bool (*policy_fn_t)(int type, int *oldtype);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setcanceltype_policy");
    if (policy && !policy(type, oldtype))
        abort();
    return pthread_setcanceltype(type, oldtype);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setconcurrency_wrapper(int new_level)
{
    typedef bool (*policy_fn_t)(int new_level);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setconcurrency_policy");
    if (policy && !policy(new_level))
        abort();
    return pthread_setconcurrency(new_level);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setname_np_wrapper(pthread_t thread, const char *name)
{
    typedef bool (*policy_fn_t)(pthread_t thread, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setname_np_policy");
    if (policy && !policy(thread, name))
        abort();
    return pthread_setname_np(thread, name);
}

#include <pthread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setschedparam_wrapper(pthread_t thread, int policy, const struct sched_param *param)
{
    typedef bool (*policy_fn_t)(pthread_t thread, int policy, const struct sched_param *param);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setschedparam_policy");
    if (policy_fn && !policy_fn(thread, policy, param))
        abort();
    return pthread_setschedparam(thread, policy, param);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_setschedprio_wrapper(pthread_t thread, int prio)
{
    typedef bool (*policy_fn_t)(pthread_t thread, int prio);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_setschedprio_policy");
    if (policy && !policy(thread, prio))
        abort();
    return pthread_setschedprio(thread, prio);
}

#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_sigmask_wrapper(int how, const sigset_t *set, sigset_t *oldset)
{
    typedef bool (*policy_fn_t)(int how, const sigset_t *set, sigset_t *oldset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_sigmask_policy");
    if (policy && !policy(how, set, oldset))
        abort();
    return pthread_sigmask(how, set, oldset);
}

#include <signal.h>
#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_sigqueue_wrapper(pthread_t thread, int sig, const union sigval value)
{
    typedef bool (*policy_fn_t)(pthread_t thread, int sig, const union sigval value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_sigqueue_policy");
    if (policy && !policy(thread, sig, value))
        abort();
    return pthread_sigqueue(thread, sig, value);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_spin_destroy_wrapper(pthread_spinlock_t *lock)
{
    typedef bool (*policy_fn_t)(pthread_spinlock_t *lock);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_spin_destroy_policy");
    if (policy && !policy(lock))
        abort();
    return pthread_spin_destroy(lock);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_spin_init_wrapper(pthread_spinlock_t *lock, int pshared)
{
    typedef bool (*policy_fn_t)(pthread_spinlock_t *lock, int pshared);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_spin_init_policy");
    if (policy && !policy(lock, pshared))
        abort();
    return pthread_spin_init(lock, pshared);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_spin_lock_wrapper(pthread_spinlock_t *lock)
{
    typedef bool (*policy_fn_t)(pthread_spinlock_t *lock);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_spin_lock_policy");
    if (policy && !policy(lock))
        abort();
    return pthread_spin_lock(lock);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_spin_trylock_wrapper(pthread_spinlock_t *lock)
{
    typedef bool (*policy_fn_t)(pthread_spinlock_t *lock);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_spin_trylock_policy");
    if (policy && !policy(lock))
        abort();
    return pthread_spin_trylock(lock);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_spin_unlock_wrapper(pthread_spinlock_t *lock)
{
    typedef bool (*policy_fn_t)(pthread_spinlock_t *lock);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_spin_unlock_policy");
    if (policy && !policy(lock))
        abort();
    return pthread_spin_unlock(lock);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void pthread_testcancel_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_testcancel_policy");
    if (policy && !policy())
        abort();
    pthread_testcancel();
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_timedjoin_np_wrapper(pthread_t thread, void **retval, const struct timespec *abstime)
{
    typedef bool (*policy_fn_t)(pthread_t thread, void **retval, const struct timespec *abstime);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_timedjoin_np_policy");
    if (policy && !policy(thread, retval, abstime))
        abort();
    return pthread_timedjoin_np(thread, retval, abstime);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_tryjoin_np_wrapper(pthread_t thread, void **retval)
{
    typedef bool (*policy_fn_t)(pthread_t thread, void **retval);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_tryjoin_np_policy");
    if (policy && !policy(thread, retval))
        abort();
    return pthread_tryjoin_np(thread, retval);
}

#include <pthread.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int pthread_yield_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pthread_yield_policy");
    if (policy && !policy())
        abort();
    return pthread_yield();
}

#include <sys/ptrace.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long ptrace_wrapper(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
    typedef bool (*policy_fn_t)(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ptrace_policy");
    if (policy && !policy(request, pid, addr, data))
        abort();
    return ptrace(request, pid, addr, data);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ptsname_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ptsname_policy");
    if (policy && !policy(fd))
        abort();
    return ptsname(fd);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ptsname_r_wrapper(int fd, char *buf, size_t buflen)
{
    typedef bool (*policy_fn_t)(int fd, char *buf, size_t buflen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ptsname_r_policy");
    if (policy && !policy(fd, buf, buflen))
        abort();
    return ptsname_r(fd, buf, buflen);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putc_wrapper(int c, FILE *stream)
{
    //wakka printffrom putc\n");
    typedef bool (*policy_fn_t)(int c, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putc_policy");
    if (policy && !policy(c, stream))
        abort();
    return putc(c, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putc_unlocked_wrapper(int c, FILE *stream)
{
    typedef bool (*policy_fn_t)(int c, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putc_unlocked_policy");
    if (policy && !policy(c, stream))
        abort();
    return putc_unlocked(c, stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putchar_wrapper(int c)
{
    //wakka printffrom putchar\n");
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putchar_policy");
    if (policy && !policy(c))
        abort();
    return putchar(c);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putchar_unlocked_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putchar_unlocked_policy");
    if (policy && !policy(c))
        abort();
    return putchar_unlocked(c);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putenv_wrapper(char *string)
{
    typedef bool (*policy_fn_t)(char *string);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putenv_policy");
    if (policy && !policy(string))
        abort();
    return putenv(string);
}

#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putgrent_wrapper(const struct group *grp, FILE *stream)
{
    typedef bool (*policy_fn_t)(const struct group *grp, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putgrent_policy");
    if (policy && !policy(grp, stream))
        abort();
    return putgrent(grp, stream);
}

#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putpwent_wrapper(const struct passwd *p, FILE *stream)
{
    typedef bool (*policy_fn_t)(const struct passwd *p, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putpwent_policy");
    if (policy && !policy(p, stream))
        abort();
    return putpwent(p, stream);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int puts_wrapper(const char *s)
{
     printf("hello from puts");
    typedef bool (*policy_fn_t)(const char *s);

    // 2) inline logging (open/close per call; no globals)
    FILE *logf = fopen("/tmp/puts_log.txt", "w");
    if (logf)
    {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        fprintf(logf, "[%02d:%02d:%02d] puts(s=\"%s\")\n",
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                s ? s : "(null)");
        fclose(logf);
    }

    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "puts_policy");
    if (policy && !policy(s))
        abort();
    mpk_entry_gate();
    int ret =  puts(s);
    mpk_exit_gate();
    return ret;
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putspent_wrapper(const struct spwd *p, FILE *stream)
{
    typedef bool (*policy_fn_t)(const struct spwd *p, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putspent_policy");
    if (policy && !policy(p, stream))
        abort();
    return putspent(p, stream);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmp *pututline_wrapper(const struct utmp *ut)
{
    typedef bool (*policy_fn_t)(const struct utmp *ut);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pututline_policy");
    if (policy && !policy(ut))
        abort();
    return pututline(ut);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct utmpx *pututxline_wrapper(const struct utmpx *ut)
{
    typedef bool (*policy_fn_t)(const struct utmpx *);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pututxline_policy");
    if (policy && !policy(ut))
        abort(); // pass the argument

    return pututxline(ut); // pass the argument
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int putw_wrapper(int w, FILE *stream)
{
    typedef bool (*policy_fn_t)(int w, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putw_policy");
    if (policy && !policy(w, stream))
        abort();
    return putw(w, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t putwc_wrapper(wchar_t wc, FILE *stream)
{
    typedef bool (*policy_fn_t)(wchar_t wc, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putwc_policy");
    if (policy && !policy(wc, stream))
        abort();
    return putwc(wc, stream);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t putwc_unlocked_wrapper(wchar_t wc, FILE *stream)
{
    typedef bool (*policy_fn_t)(wchar_t wc, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putwc_unlocked_policy");
    if (policy && !policy(wc, stream))
        abort();
    return putwc_unlocked(wc, stream);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t putwchar_wrapper(wchar_t wc)
{
    typedef bool (*policy_fn_t)(wchar_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putwchar_policy");
    if (policy && !policy(wc))
        abort();
    return putwchar(wc);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t putwchar_unlocked_wrapper(wchar_t wc)
{
    typedef bool (*policy_fn_t)(wchar_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "putwchar_unlocked_policy");
    if (policy && !policy(wc))
        abort();
    return putwchar_unlocked(wc);
}

#include <stdlib.h>
#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *pvalloc_wrapper(size_t size)
{
    typedef bool (*policy_fn_t)(size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pvalloc_policy");
    if (policy && !policy(size))
        abort();
    return pvalloc(size);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t pwrite_wrapper(int fd, const void *buf, size_t count, off_t offset)
{
    typedef bool (*policy_fn_t)(int fd, const void *buf, size_t count, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pwrite_policy");
    if (policy && !policy(fd, buf, count, offset))
        abort();
    return pwrite(fd, buf, count, offset);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t pwrite64_wrapper(int fd, const void *buf, size_t count, off_t offset)
{
    typedef bool (*policy_fn_t)(int fd, const void *buf, size_t count, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pwrite64_policy");
    if (policy && !policy(fd, buf, count, offset))
        abort();
    return pwrite64(fd, buf, count, offset);
}

#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t pwritev_wrapper(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, int iovcnt, off_t offset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pwritev_policy");
    if (policy && !policy(fd, iov, iovcnt, offset))
        abort();
    return pwritev(fd, iov, iovcnt, offset);
}

#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t pwritev2_wrapper(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags)
{
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "pwritev2_policy");
    if (policy && !policy(fd, iov, iovcnt, offset, flags))
        abort();
    return pwritev2(fd, iov, iovcnt, offset, flags);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *qecvt_wrapper(long double number, int ndigits, int *decpt, int *sign)
{
    typedef bool (*policy_fn_t)(long double number, int ndigits, int *decpt, int *sign);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qecvt_policy");
    if (policy && !policy(number, ndigits, decpt, sign))
        abort();
    return qecvt(number, ndigits, decpt, sign);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int qecvt_r_wrapper(long double number, int ndigits, int *decpt, int *sign, char *buf, size_t len)
{
    typedef bool (*policy_fn_t)(long double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qecvt_r_policy");
    if (policy && !policy(number, ndigits, decpt, sign, buf, len))
        abort();
    return qecvt_r(number, ndigits, decpt, sign, buf, len);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *qfcvt_wrapper(long double number, int ndigits, int *decpt, int *sign)
{
    typedef bool (*policy_fn_t)(long double number, int ndigits, int *decpt, int *sign);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qfcvt_policy");
    if (policy && !policy(number, ndigits, decpt, sign))
        abort();
    return qfcvt(number, ndigits, decpt, sign);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int qfcvt_r_wrapper(long double number, int ndigits, int *decpt, int *sign, char *buf, size_t len)
{
    typedef bool (*policy_fn_t)(long double number, int ndigits, int *decpt, int *sign, char *buf, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qfcvt_r_policy");
    if (policy && !policy(number, ndigits, decpt, sign, buf, len))
        abort();
    return qfcvt_r(number, ndigits, decpt, sign, buf, len);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *qgcvt_wrapper(long double number, int ndigit, char *buf)
{
    typedef bool (*policy_fn_t)(long double number, int ndigit, char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qgcvt_policy");
    if (policy && !policy(number, ndigit, buf))
        abort();
    return qgcvt(number, ndigit, buf);
}

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void qsort_wrapper(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qsort_policy");
    if (policy && !policy(base, nmemb, size, compar))
        abort();
    qsort(base, nmemb, size, compar);
}

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void qsort_r_wrapper(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void *arg)
{
    typedef bool (*policy_fn_t)(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void *arg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "qsort_r_policy");
    if (policy && !policy(base, nmemb, size, compar, arg))
        abort();
    qsort_r(base, nmemb, size, compar, arg);
}

// #include <linux/module.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int query_module_wrapper(const char *name, int which, void *buf, size_t bufsize, size_t *ret)
// {
//     typedef bool (*policy_fn_t)(const char *name, int which, void *buf, size_t bufsize, size_t *ret);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "query_module_policy");
//     if (policy && !policy(name, which, buf, bufsize, ret))
//         abort();
//     return query_module(name, which, buf, bufsize, ret);
// }

// #include <sys/quota.h>
// #include <xfs/xqm.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int quotactl_wrapper(int cmd, const char *special, int id, caddr_t addr) {
//     typedef bool (*policy_fn_t)(int cmd, const char *special, int id, caddr_t addr);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "quotactl_policy");
//     if(policy && !policy(cmd, special, id, addr)) abort();
//     return quotactl(cmd, special, id, addr);
// }

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int raise_wrapper(int sig)
{
    //wakka printffrom raise\n");
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "raise_policy");
    if (policy && !policy(sig))
        abort();
    return raise(sig);
}

#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rand_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rand_policy");
    if (policy && !policy())
        abort();
    return rand();
}

#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rand_r_wrapper(unsigned int *seedp)
{
    typedef bool (*policy_fn_t)(unsigned int *seedp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rand_r_policy");
    if (policy && !policy(seedp))
        abort();
    return rand_r(seedp);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long random_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "random_policy");
    if (policy && !policy())
        abort();
    return random();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int random_r_wrapper(struct random_data *buf, int32_t *result)
{
    typedef bool (*policy_fn_t)(struct random_data *buf, int32_t *result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "random_r_policy");
    if (policy && !policy(buf, result))
        abort();
    return random_r(buf, result);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *rawmemchr_wrapper(void *s, int c)
{
    typedef bool (*policy_fn_t)(void *s, int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rawmemchr_policy");
    if (policy && !policy(s, c))
        abort();
    return rawmemchr(s, c);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rcmd_wrapper(char **ahost, unsigned short inport, const char *locuser, const char *remuser, const char *cmd, int *fd2p)
{
    typedef bool (*policy_fn_t)(char **ahost, unsigned short inport, const char *locuser, const char *remuser, const char *cmd, int *fd2p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rcmd_policy");
    if (policy && !policy(ahost, inport, locuser, remuser, cmd, fd2p))
        abort();
    return rcmd(ahost, inport, locuser, remuser, cmd, fd2p);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rcmd_af_wrapper(char **ahost, unsigned short inport, const char *locuser, const char *remuser, const char *cmd, int *fd2p, sa_family_t af)
{
    typedef bool (*policy_fn_t)(char **ahost, unsigned short inport, const char *locuser, const char *remuser, const char *cmd, int *fd2p, sa_family_t af);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rcmd_af_policy");
    if (policy && !policy(ahost, inport, locuser, remuser, cmd, fd2p, af))
        abort();
    return rcmd_af(ahost, inport, locuser, remuser, cmd, fd2p, af);
}

// #include <sys/types.h>
// #include <regex.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// char *re_comp_wrapper(const char *regex)
// {
//     typedef bool (*policy_fn_t)(const char *regex);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "re_comp_policy");
//     if (policy && !policy(regex))
//         abort();
//     return re_comp(regex);
// }

// #include <sys/types.h>
// #include <regex.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int re_exec_wrapper(const char *string)
// {
//     typedef bool (*policy_fn_t)(const char *string);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "re_exec_policy");
//     if (policy && !policy(string))
//         abort();
//     return re_exec(string);
// }

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t read_wrapper(int fd, void *buf, size_t count)
{
    FILE *out = fopen("read.txt", "a"); // append mode, create if not exist
    if (!out)
    {
        perror("fopen");
        return 0;
    }

    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);

    char target[PATH_MAX];
    ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n >= 0)
    {
        target[n] = '\0';
        fprintf(out, "read(fd=%d, count=%zu) -> %s\n", fd, count, target);
    }
    else
    {
        fprintf(out, "read(fd=%d, count=%zu) -> <unknown> (readlink: %s)\n",
                fd, count, strerror(errno));
    }

    fclose(out);

    typedef bool (*policy_fn_t)(int fd, void *buf, size_t count);

    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "read_policy");
    if (policy && !policy(fd, buf, count))
        abort();
    return read(fd, buf, count);
}

#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t readahead_wrapper(int fd, off64_t offset, size_t count)
{
    typedef bool (*policy_fn_t)(int fd, off64_t offset, size_t count);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "readahead_policy");
    if (policy && !policy(fd, offset, count))
        abort();
    return readahead(fd, offset, count);
}

#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int readdir_r_wrapper(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    typedef bool (*policy_fn_t)(DIR *dirp, struct dirent *entry, struct dirent **result);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "readdir_r_policy");
    if (policy && !policy(dirp, entry, result))
        abort();
    return readdir_r(dirp, entry, result);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t readlink_wrapper(const char *pathname, char *buf, size_t bufsiz)
{
    typedef bool (*policy_fn_t)(const char *pathname, char *buf, size_t bufsiz);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "readlink_policy");
    if (policy && !policy(pathname, buf, bufsiz))
        abort();
    return readlink(pathname, buf, bufsiz);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t readlinkat_wrapper(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, char *buf, size_t bufsiz);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "readlinkat_policy");
    if (policy && !policy(dirfd, pathname, buf, bufsiz))
        abort();
    return readlinkat(dirfd, pathname, buf, bufsiz);
}

#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t readv_wrapper(int fd, const struct iovec *iov, int iovcnt)
{
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, int iovcnt);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "readv_policy");
    if (policy && !policy(fd, iov, iovcnt))
        abort();
    return readv(fd, iov, iovcnt);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *realloc_wrapper(void *ptr, size_t size)
{
    typedef bool (*policy_fn_t)(void *ptr, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "realloc_policy");
    if (policy && !policy(ptr, size))
        abort();
    return realloc(ptr, size);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *reallocarray_wrapper(void *ptr, size_t nmemb, size_t size)
{
    typedef bool (*policy_fn_t)(void *ptr, size_t nmemb, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "reallocarray_policy");
    if (policy && !policy(ptr, nmemb, size))
        abort();
    return reallocarray(ptr, nmemb, size);
}

#include <limits.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *realpath_wrapper(const char *path, char *resolved_path)
{
    typedef bool (*policy_fn_t)(const char *path, char *resolved_path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "realpath_policy");
    if (policy && !policy(path, resolved_path))
        abort();
    return realpath(path, resolved_path);
}

#include <sys/syscall.h>
#include <unistd.h>

int reboot_wrapper(int magic, int magic2, int cmd, void *arg)
{
    typedef bool (*policy_fn_t)(int magic, int magic2, int cmd, void *arg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "reboot_policy");
    if (policy && !policy(magic, magic2, cmd, arg))
        abort();
    return syscall(SYS_reboot, magic, magic2, cmd, arg); // calls kernel directly
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t recv_wrapper(int sockfd, void *buf, size_t len, int flags)
{
    //wakka printffrom recv\n");
    typedef bool (*policy_fn_t)(int sockfd, void *buf, size_t len, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "recv_policy");
    if (policy && !policy(sockfd, buf, len, flags))
        abort();
    return recv(sockfd, buf, len, flags);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t recvfrom_wrapper(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    //wakka printffrom recvfrom\n");
    typedef bool (*policy_fn_t)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "recvfrom_policy");
    if (policy && !policy(sockfd, buf, len, flags, src_addr, addrlen))
        abort();
    return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int recvmmsg_wrapper(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout)
{
    typedef bool (*policy_fn_t)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "recvmmsg_policy");
    if (policy && !policy(sockfd, msgvec, vlen, flags, timeout))
        abort();
    return recvmmsg(sockfd, msgvec, vlen, flags, timeout);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t recvmsg_wrapper(int sockfd, struct msghdr *msg, int flags)
{
    typedef bool (*policy_fn_t)(int sockfd, struct msghdr *msg, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "recvmsg_policy");
    if (policy && !policy(sockfd, msg, flags))
        abort();
    return recvmsg(sockfd, msg, flags);
}

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int regcomp_wrapper(regex_t *preg, const char *regex, int cflags)
{
    typedef bool (*policy_fn_t)(regex_t *preg, const char *regex, int cflags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "regcomp_policy");
    if (policy && !policy(preg, regex, cflags))
        abort();
    return regcomp(preg, regex, cflags);
}

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t regerror_wrapper(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
{
    typedef bool (*policy_fn_t)(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "regerror_policy");
    if (policy && !policy(errcode, preg, errbuf, errbuf_size))
        abort();
    return regerror(errcode, preg, errbuf, errbuf_size);
}

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int regexec_wrapper(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
{
    typedef bool (*policy_fn_t)(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "regexec_policy");
    if (policy && !policy(preg, string, nmatch, pmatch, eflags))
        abort();
    return regexec(preg, string, nmatch, pmatch, eflags);
}

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void regfree_wrapper(regex_t *preg)
{
    typedef bool (*policy_fn_t)(regex_t *preg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "regfree_policy");
    if (policy && !policy(preg))
        abort();
    regfree(preg);
}

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int registerrpc_wrapper(unsigned long prognum, unsigned long versnum, unsigned long procnum, char *(*procname)(char *), xdrproc_t inproc, xdrproc_t outproc)
// {
//     typedef bool (*policy_fn_t)(unsigned long prognum, unsigned long versnum, unsigned long procnum, char *(*procname)(char *), xdrproc_t inproc, xdrproc_t outproc);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "registerrpc_policy");
//     if (policy && !policy(prognum, versnum, procnum, procname, inproc, outproc))
//         abort();
//     return registerrpc(prognum, versnum, procnum, procname, inproc, outproc);
// }

#include <sys/mman.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int remap_file_pages_wrapper(void *addr, size_t size, int prot, size_t pgoff, int flags)
{
    typedef bool (*policy_fn_t)(void *addr, size_t size, int prot, size_t pgoff, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "remap_file_pages_policy");
    if (policy && !policy(addr, size, prot, pgoff, flags))
        abort();
    return remap_file_pages(addr, size, prot, pgoff, flags);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int remove_wrapper(const char *pathname)
{
    typedef bool (*policy_fn_t)(const char *pathname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "remove_policy");
    if (policy && !policy(pathname))
        abort();
    return remove(pathname);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int removexattr_wrapper(const char *path, const char *name)
{
    typedef bool (*policy_fn_t)(const char *path, const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "removexattr_policy");
    if (policy && !policy(path, name))
        abort();
    return removexattr(path, name);
}

#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void remque_wrapper(void *elem)
{
    typedef bool (*policy_fn_t)(void *elem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "remque_policy");
    if (policy && !policy(elem))
        abort();
    remque(elem);
}

#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rename_wrapper(const char *oldpath, const char *newpath)
{
    typedef bool (*policy_fn_t)(const char *oldpath, const char *newpath);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rename_policy");
    if (policy && !policy(oldpath, newpath))
        abort();
    return rename(oldpath, newpath);
}

#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int renameat_wrapper(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    typedef bool (*policy_fn_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "renameat_policy");
    if (policy && !policy(olddirfd, oldpath, newdirfd, newpath))
        abort();
    return renameat(olddirfd, oldpath, newdirfd, newpath);
}

#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int renameat2_wrapper(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
    typedef bool (*policy_fn_t)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "renameat2_policy");
    if (policy && !policy(olddirfd, oldpath, newdirfd, newpath, flags))
        abort();
    return renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_mkquery_wrapper(int op, const char *dname, int cls, int type, const unsigned char *data, int datalen, const unsigned char *newrr, unsigned char *buf, int buflen)
{
    typedef bool (*policy_fn_t)(int op, const char *dname, int cls, int type, const unsigned char *data, int datalen, const unsigned char *newrr, unsigned char *buf, int buflen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_mkquery_policy");
    if (policy && !policy(op, dname, cls, type, data, datalen, newrr, buf, buflen))
        abort();
    return res_mkquery(op, dname, cls, type, data, datalen, newrr, buf, buflen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_nmkquery_wrapper(res_state statep, int op, const char *dname, int cls, int type, const unsigned char *data, int datalen, const unsigned char *newrr, unsigned char *buf, int buflen)
{
    typedef bool (*policy_fn_t)(res_state statep, int op, const char *dname, int cls, int type, const unsigned char *data, int datalen, const unsigned char *newrr, unsigned char *buf, int buflen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_nmkquery_policy");
    if (policy && !policy(statep, op, dname, cls, type, data, datalen, newrr, buf, buflen))
        abort();
    return res_nmkquery(statep, op, dname, cls, type, data, datalen, newrr, buf, buflen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_nquery_wrapper(res_state statep, const char *dname, int cls, int type, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(res_state statep, const char *dname, int cls, int type, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_nquery_policy");
    if (policy && !policy(statep, dname, cls, type, answer, anslen))
        abort();
    return res_nquery(statep, dname, cls, type, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_nquerydomain_wrapper(res_state statep, const char *name, const char *domain, int cls, int type, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(res_state statep, const char *name, const char *domain, int cls, int type, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_nquerydomain_policy");
    if (policy && !policy(statep, name, domain, cls, type, answer, anslen))
        abort();
    return res_nquerydomain(statep, name, domain, cls, type, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_nsearch_wrapper(res_state statep, const char *dname, int cls, int type, unsigned char *answer, int anslen)
{
    //wakka printfFrom res_nsearch\n");
    typedef bool (*policy_fn_t)(res_state statep, const char *dname, int cls, int type, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_nsearch_policy");
    if (policy && !policy(statep, dname, cls, type, answer, anslen))
        abort();
    return res_nsearch(statep, dname, cls, type, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_nsend_wrapper(res_state statep, const unsigned char *msg, int msglen, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(res_state statep, const unsigned char *msg, int msglen, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_nsend_policy");
    if (policy && !policy(statep, msg, msglen, answer, anslen))
        abort();
    return res_nsend(statep, msg, msglen, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_query_wrapper(const char *dname, int cls, int type, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(const char *dname, int cls, int type, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_query_policy");
    if (policy && !policy(dname, cls, type, answer, anslen))
        abort();
    return res_query(dname, cls, type, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_querydomain_wrapper(const char *name, const char *domain, int cls, int type, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(const char *name, const char *domain, int cls, int type, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_querydomain_policy");
    if (policy && !policy(name, domain, cls, type, answer, anslen))
        abort();
    return res_querydomain(name, domain, cls, type, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_search_wrapper(const char *dname, int cls, int type, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(const char *dname, int cls, int type, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_search_policy");
    if (policy && !policy(dname, cls, type, answer, anslen))
        abort();
    return res_search(dname, cls, type, answer, anslen);
}

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int res_send_wrapper(const unsigned char *msg, int msglen, unsigned char *answer, int anslen)
{
    typedef bool (*policy_fn_t)(const unsigned char *msg, int msglen, unsigned char *answer, int anslen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "res_send_policy");
    if (policy && !policy(msg, msglen, answer, anslen))
        abort();
    return res_send(msg, msglen, answer, anslen);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void rewind_wrapper(FILE *stream)
{
    //wakka printffrom rewind\n");
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rewind_policy");
    if (policy && !policy(stream))
        abort();
    rewind(stream);
}

#include <sys/types.h>
#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void rewinddir_wrapper(DIR *dirp)
{
    typedef bool (*policy_fn_t)(DIR *dirp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rewinddir_policy");
    if (policy && !policy(dirp))
        abort();
    rewinddir(dirp);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rexec_wrapper(char **ahost, int inport, const char *user, const char *passwd, const char *cmd, int *fd2p)
{
    typedef bool (*policy_fn_t)(char **ahost, int inport, const char *user, const char *passwd, const char *cmd, int *fd2p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rexec_policy");
    if (policy && !policy(ahost, inport, user, passwd, cmd, fd2p))
        abort();
    return rexec(ahost, inport, user, passwd, cmd, fd2p);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rexec_af_wrapper(char **ahost, int inport, const char *user, const char *passwd, const char *cmd, int *fd2p, sa_family_t af)
{
    typedef bool (*policy_fn_t)(char **ahost, int inport, const char *user, const char *passwd, const char *cmd, int *fd2p, sa_family_t af);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rexec_af_policy");
    if (policy && !policy(ahost, inport, user, passwd, cmd, fd2p, af))
        abort();
    return rexec_af(ahost, inport, user, passwd, cmd, fd2p, af);
}

#include <strings.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *rindex_wrapper(char *s, int c)
{
    typedef bool (*policy_fn_t)(char *s, int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rindex_policy");
    if (policy && !policy(s, c))
        abort();
    return rindex(s, c);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rmdir_wrapper(const char *pathname)
{
    typedef bool (*policy_fn_t)(const char *pathname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rmdir_policy");
    if (policy && !policy(pathname))
        abort();
    return rmdir(pathname);
}

#include <stdlib.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rpmatch_wrapper(const char *response)
{
    typedef bool (*policy_fn_t)(const char *response);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rpmatch_policy");
    if (policy && !policy(response))
        abort();
    return rpmatch(response);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rresvport_wrapper(int *port)
{
    typedef bool (*policy_fn_t)(int *port);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rresvport_policy");
    if (policy && !policy(port))
        abort();
    return rresvport(port);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int rresvport_af_wrapper(int *port, sa_family_t af)
{
    typedef bool (*policy_fn_t)(int *port, sa_family_t af);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rresvport_af_policy");
    if (policy && !policy(port, af))
        abort();
    return rresvport_af(port, af);
}

// // #include <rpc/auth_des.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <errno.h>
// #include <string.h>
// #include <time.h>
// // #include <rpc/auth_des.h>
// #include <netdb.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int rtime_wrapper(struct sockaddr_in *addrp, struct rpc_timeval *timep, struct rpc_timeval *timeout)
// {
//     typedef bool (*policy_fn_t)(struct sockaddr_in *addrp, struct rpc_timeval *timep, struct rpc_timeval *timeout);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "rtime_policy");
//     if (policy && !policy(addrp, timep, timeout))
//         abort();
//     return rtime(addrp, timep, timeout);
// }

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ruserok_wrapper(const char *rhost,
                    int superuser,
                    const char *ruser,
                    const char *luser)
{
    typedef bool (*policy_fn_t)(const char *rhost,
                                int superuser,
                                const char *ruser,
                                const char *luser);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "ruserok_policy");
    if (policy && !policy(rhost, superuser, ruser, luser))
        abort();

    return ruserok(rhost, superuser, ruser, luser);
}


#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>
int ruserok_af_wrapper(const char *rhost,
                       int superuser,
                       const char *ruser,
                       const char *luser,
                       sa_family_t af)
{
    typedef bool (*policy_fn_t)(const char *rhost,
                                int superuser,
                                const char *ruser,
                                const char *luser,
                                sa_family_t af);

    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "ruserok_af_policy");

    if (policy && !policy(rhost, superuser, ruser, luser, af))
        abort();

    return ruserok_af(rhost, superuser, ruser, luser, af);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *sbrk_wrapper(intptr_t increment)
{
    typedef bool (*policy_fn_t)(intptr_t increment);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sbrk_policy");
    if (policy && !policy(increment))
        abort();
    return sbrk(increment);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double scalbn_wrapper(double x, int exp)
{
    typedef bool (*policy_fn_t)(double x, int exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "scalbn_policy");
    if (policy && !policy(x, exp))
        abort();
    return scalbn(x, exp);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

float scalbnf_wrapper(float x, int exp)
{
    typedef bool (*policy_fn_t)(float x, int exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "scalbnf_policy");
    if (policy && !policy(x, exp))
        abort();
    return scalbnf(x, exp);
}

#include <math.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long double scalbnl_wrapper(long double x, int exp)
{
    typedef bool (*policy_fn_t)(long double x, int exp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "scalbnl_policy");
    if (policy && !policy(x, exp))
        abort();
    return scalbnl(x, exp);
}

#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int scandir_wrapper(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))
{
    typedef bool (*policy_fn_t)(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "scandir_policy");
    if (policy && !policy(dirp, namelist, filter, compar))
        abort();
    return scandir(dirp, namelist, filter, compar);
}

#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int scandirat_wrapper(int dirfd, const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))
{
    typedef bool (*policy_fn_t)(int dirfd, const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "scandirat_policy");
    if (policy && !policy(dirfd, dirp, namelist, filter, compar))
        abort();
    return scandirat(dirfd, dirp, namelist, filter, compar);
}

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <stdbool.h>

int scanf_wrapper(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // Collect pointers from variadic args into an array
    void *var_argv[64];
    int vi = 0;
    void *next_ptr;
    while (vi < 64 && (next_ptr = va_arg(args, void *)) != NULL)
    {
        var_argv[vi++] = next_ptr;
    }

    // Call policy function
    typedef bool (*policy_fn_t)(const char *format, void *var_argv[], int nargs);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "scanf_policy");
    if (policy && !policy(format, var_argv, vi))
    {
        va_end(args);
        abort();
    }

    // Since we consumed va_list for policy, we need to restart it to call vscanf
    va_end(args);
    va_start(args, format);
    int ret = vscanf(format, args);
    va_end(args);
    return ret;
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_get_priority_max_wrapper(int policy)
{
    typedef bool (*policy_fn_t)(int policy);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "sched_get_priority_max_policy");
    if (policy_fn && !policy_fn(policy))
        abort();
    return sched_get_priority_max(policy);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_get_priority_min_wrapper(int policy)
{
    typedef bool (*policy_fn_t)(int policy);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "sched_get_priority_min_policy");
    if (policy_fn && !policy_fn(policy))
        abort();
    return sched_get_priority_min(policy);
}

#include <sched.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_getaffinity_wrapper(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
{
    typedef bool (*policy_fn_t)(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_getaffinity_policy");
    if (policy && !policy(pid, cpusetsize, mask))
        abort();
    return sched_getaffinity(pid, cpusetsize, mask);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_getcpu_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_getcpu_policy");
    if (policy && !policy())
        abort();
    return sched_getcpu();
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_getparam_wrapper(pid_t pid, struct sched_param *param)
{
    typedef bool (*policy_fn_t)(pid_t pid, struct sched_param *param);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_getparam_policy");
    if (policy && !policy(pid, param))
        abort();
    return sched_getparam(pid, param);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_getscheduler_wrapper(pid_t pid)
{
    typedef bool (*policy_fn_t)(pid_t pid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_getscheduler_policy");
    if (policy && !policy(pid))
        abort();
    return sched_getscheduler(pid);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_rr_get_interval_wrapper(pid_t pid, struct timespec *tp)
{
    typedef bool (*policy_fn_t)(pid_t pid, struct timespec *tp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_rr_get_interval_policy");
    if (policy && !policy(pid, tp))
        abort();
    return sched_rr_get_interval(pid, tp);
}

#include <sched.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_setaffinity_wrapper(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)
{
    typedef bool (*policy_fn_t)(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_setaffinity_policy");
    if (policy && !policy(pid, cpusetsize, mask))
        abort();
    return sched_setaffinity(pid, cpusetsize, mask);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_setparam_wrapper(pid_t pid, const struct sched_param *param)
{
    typedef bool (*policy_fn_t)(pid_t pid, const struct sched_param *param);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_setparam_policy");
    if (policy && !policy(pid, param))
        abort();
    return sched_setparam(pid, param);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_setscheduler_wrapper(pid_t pid, int policy, const struct sched_param *param)
{
    typedef bool (*policy_fn_t)(pid_t pid, int policy, const struct sched_param *param);
    policy_fn_t policy_fn = (policy_fn_t)dlsym(RTLD_NEXT, "sched_setscheduler_policy");
    if (policy_fn && !policy_fn(pid, policy, param))
        abort();
    return sched_setscheduler(pid, policy, param);
}

#include <sched.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sched_yield_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sched_yield_policy");
    if (policy && !policy())
        abort();
    return sched_yield();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *secure_getenv_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "secure_getenv_policy");
    if (policy && !policy(name))
        abort();
    return secure_getenv(name);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned short *seed48_wrapper(unsigned short seed16v[3])
{
    typedef bool (*policy_fn_t)(unsigned short seed16v[3]);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "seed48_policy");

    if (policy && !policy(seed16v))
        abort();

    return seed48(seed16v);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int seed48_r_wrapper(unsigned short seed16v[3],
                     struct drand48_data *buffer)
{
    typedef bool (*policy_fn_t)(unsigned short seed16v[3],
                                struct drand48_data *buffer);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "seed48_r_policy");

    if (policy && !policy(seed16v, buffer))
        abort();

    return seed48_r(seed16v, buffer);
}

#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void seekdir_wrapper(DIR *dirp, long loc)
{
    typedef bool (*policy_fn_t)(DIR *dirp, long loc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "seekdir_policy");
    if (policy && !policy(dirp, loc))
        abort();
    seekdir(dirp, loc);
}

#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int select_wrapper(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    //wakka printffrom select\n");
    typedef bool (*policy_fn_t)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "select_policy");
    if (policy && !policy(nfds, readfds, writefds, exceptfds, timeout))
        abort();
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_close_wrapper(sem_t *sem)
{
    typedef bool (*policy_fn_t)(sem_t *sem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_close_policy");
    if (policy && !policy(sem))
        abort();
    return sem_close(sem);
}

#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_destroy_wrapper(sem_t *sem)
{
    typedef bool (*policy_fn_t)(sem_t *sem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_destroy_policy");
    if (policy && !policy(sem))
        abort();
    return sem_destroy(sem);
}

#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_getvalue_wrapper(sem_t *sem, int *sval)
{
    typedef bool (*policy_fn_t)(sem_t *sem, int *sval);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_getvalue_policy");
    if (policy && !policy(sem, sval))
        abort();
    return sem_getvalue(sem, sval);
}

#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_init_wrapper(sem_t *sem, int pshared, unsigned int value)
{
    typedef bool (*policy_fn_t)(sem_t *sem, int pshared, unsigned int value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_init_policy");
    if (policy && !policy(sem, pshared, value))
        abort();
    return sem_init(sem, pshared, value);
}

#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

sem_t *sem_open_wrapper(const char *name, int oflag)
{
    typedef bool (*policy_fn_t)(const char *name, int oflag);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_open_policy");
    if (policy && !policy(name, oflag))
        abort();
    return sem_open(name, oflag);
}

#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_post_wrapper(sem_t *sem)
{
    typedef bool (*policy_fn_t)(sem_t *sem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_post_policy");
    if (policy && !policy(sem))
        abort();
    return sem_post(sem);
}

#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_timedwait_wrapper(sem_t *sem, const struct timespec *abs_timeout)
{
    typedef bool (*policy_fn_t)(sem_t *sem, const struct timespec *abs_timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_timedwait_policy");
    if (policy && !policy(sem, abs_timeout))
        abort();
    return sem_timedwait(sem, abs_timeout);
}

#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_trywait_wrapper(sem_t *sem)
{
    typedef bool (*policy_fn_t)(sem_t *sem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_trywait_policy");
    if (policy && !policy(sem))
        abort();
    return sem_trywait(sem);
}

#include <semaphore.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_unlink_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_unlink_policy");
    if (policy && !policy(name))
        abort();
    return sem_unlink(name);
}

#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sem_wait_wrapper(sem_t *sem)
{
    typedef bool (*policy_fn_t)(sem_t *sem);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sem_wait_policy");
    if (policy && !policy(sem))
        abort();
    return sem_wait(sem);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int semctl_wrapper(int semid, int semnum, int cmd, ...)
{
    va_list args;
    va_start(args, cmd);
    long var_argv[1];
    var_argv[0] = va_arg(args, long);

    typedef bool (*policy_fn_t)(int semid, int semnum, long var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "semctl_policy");
    if (policy && !policy(semid, semnum, var_argv))
    {
        va_end(args);
        abort();
    }

    va_end(args);
    return semctl(semid, semnum, cmd, var_argv[0]);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int semget_wrapper(key_t key, int nsems, int semflg)
{
    typedef bool (*policy_fn_t)(key_t key, int nsems, int semflg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "semget_policy");
    if (policy && !policy(key, nsems, semflg))
        abort();
    return semget(key, nsems, semflg);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int semop_wrapper(int semid, struct sembuf *sops, size_t nsops)
{
    typedef bool (*policy_fn_t)(int semid, struct sembuf *sops, size_t nsops);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "semop_policy");
    if (policy && !policy(semid, sops, nsops))
        abort();
    return semop(semid, sops, nsops);
}

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int semtimedop_wrapper(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout)
{
    typedef bool (*policy_fn_t)(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "semtimedop_policy");
    if (policy && !policy(semid, sops, nsops, timeout))
        abort();
    return semtimedop(semid, sops, nsops, timeout);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t send_wrapper(int sockfd, const void *buf, size_t len, int flags)
{
    //wakka printffrom send\n");
    typedef bool (*policy_fn_t)(int sockfd, const void *buf, size_t len, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "send_policy");
    if (policy && !policy(sockfd, buf, len, flags))
        abort();
    return send(sockfd, buf, len, flags);
}

#include <sys/sendfile.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t sendfile_wrapper(int out_fd, int in_fd, off_t *offset, size_t count)
{
    typedef bool (*policy_fn_t)(int out_fd, int in_fd, off_t *offset, size_t count);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sendfile_policy");
    if (policy && !policy(out_fd, in_fd, offset, count))
        abort();
    return sendfile(out_fd, in_fd, offset, count);
}

#include <sys/sendfile.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t sendfile64_wrapper(int out_fd, int in_fd, off_t *offset, size_t count)
{
    typedef bool (*policy_fn_t)(int out_fd, int in_fd, off_t *offset, size_t count);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sendfile64_policy");
    if (policy && !policy(out_fd, in_fd, offset, count))
        abort();
    return sendfile64(out_fd, in_fd, offset, count);
}

#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sendmmsg_wrapper(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
{
    typedef bool (*policy_fn_t)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sendmmsg_policy");
    if (policy && !policy(sockfd, msgvec, vlen, flags))
        abort();
    return sendmmsg(sockfd, msgvec, vlen, flags);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t sendmsg_wrapper(int sockfd, const struct msghdr *msg, int flags)
{
    //wakka printffrom sendmsg\n");
    //wakka printfsockfd : %d  flaas: %d\n", sockfd, flags);
    typedef bool (*policy_fn_t)(int sockfd, const struct msghdr *msg, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sendmsg_policy");
    if (policy && !policy(sockfd, msg, flags))
        abort();
    return sendmsg(sockfd, msg, flags);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t sendto_wrapper(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    //wakka printffrom sendto\n");
    typedef bool (*policy_fn_t)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sendto_policy");
    if (policy && !policy(sockfd, buf, len, flags, dest_addr, addrlen))
        abort();
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

#include <aliases.h>

#include <aliases.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setaliasent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setaliasent_policy");
    if (policy && !policy())
        abort();
    setaliasent();
}

#include <stdio.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setbuf_wrapper(FILE *stream, char *buf)
{
    typedef bool (*policy_fn_t)(FILE *stream, char *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setbuf_policy");
    if (policy && !policy(stream, buf))
        abort();
    setbuf(stream, buf);
}

#include <stdio.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setbuffer_wrapper(FILE *stream, char *buf, size_t size)
{
    typedef bool (*policy_fn_t)(FILE *stream, char *buf, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setbuffer_policy");
    if (policy && !policy(stream, buf, size))
        abort();
    setbuffer(stream, buf, size);
}

#include <ucontext.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setcontext_wrapper(const ucontext_t *ucp)
{
    typedef bool (*policy_fn_t)(const ucontext_t *ucp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setcontext_policy");
    if (policy && !policy(ucp))
        abort();
    return setcontext(ucp);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setdomainname_wrapper(const char *name, size_t len)
{
    typedef bool (*policy_fn_t)(const char *name, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setdomainname_policy");
    if (policy && !policy(name, len))
        abort();
    return setdomainname(name, len);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setegid_wrapper(gid_t egid)
{
    typedef bool (*policy_fn_t)(gid_t egid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setegid_policy");
    if (policy && !policy(egid))
        abort();
    return setegid(egid);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setenv_wrapper(const char *name, const char *value, int overwrite)
{
    //wakka printffrom setenv\n");
    typedef bool (*policy_fn_t)(const char *name, const char *value, int overwrite);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setenv_policy");
    if (policy && !policy(name, value, overwrite))
        abort();
    return setenv(name, value, overwrite);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int seteuid_wrapper(uid_t euid)
{
    typedef bool (*policy_fn_t)(uid_t euid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "seteuid_policy");
    if (policy && !policy(euid))
        abort();
    return seteuid(euid);
}

#include <fstab.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setfsent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setfsent_policy");
    if (policy && !policy())
        abort();
    return setfsent();
}

#include <sys/fsuid.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setfsgid_wrapper(uid_t fsgid)
{
    typedef bool (*policy_fn_t)(uid_t fsgid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setfsgid_policy");
    if (policy && !policy(fsgid))
        abort();
    return setfsgid(fsgid);
}

#include <sys/fsuid.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setfsuid_wrapper(uid_t fsuid)
{
    typedef bool (*policy_fn_t)(uid_t fsuid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setfsuid_policy");
    if (policy && !policy(fsuid))
        abort();
    return setfsuid(fsuid);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setgid_wrapper(gid_t gid)
{
    typedef bool (*policy_fn_t)(gid_t gid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setgid_policy");
    if (policy && !policy(gid))
        abort();
    return setgid(gid);
}

#include <sys/types.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setgrent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setgrent_policy");
    if (policy && !policy())
        abort();
    setgrent();
}

#include <sys/types.h>
#include <unistd.h>
#include <grp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setgroups_wrapper(size_t size, const gid_t *list)
{
    //wakka printffrom setgroups\n");
    typedef bool (*policy_fn_t)(size_t size, const gid_t *list);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setgroups_policy");
    if (policy && !policy(size, list))
        abort();
    return setgroups(size, list);
}

#include <netdb.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void sethostent_wrapper(int stayopen)
{
    typedef bool (*policy_fn_t)(int stayopen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sethostent_policy");
    if (policy && !policy(stayopen))
        abort();
    sethostent(stayopen);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sethostid_wrapper(long hostid)
{
    typedef bool (*policy_fn_t)(long hostid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sethostid_policy");
    if (policy && !policy(hostid))
        abort();
    return sethostid(hostid);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sethostname_wrapper(const char *name, size_t len)
{
    typedef bool (*policy_fn_t)(const char *name, size_t len);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sethostname_policy");
    if (policy && !policy(name, len))
        abort();
    return sethostname(name, len);
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setitimer_wrapper(int which, const struct itimerval *new_value, struct itimerval *old_value)
{
    typedef bool (*policy_fn_t)(int which, const struct itimerval *new_value, struct itimerval *old_value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setitimer_policy");
    if (policy && !policy(which, new_value, old_value))
        abort();
    return setitimer(which, new_value, old_value);
}

#include <setjmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setjmp_wrapper(jmp_buf env)
{
    typedef bool (*policy_fn_t)(jmp_buf env);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setjmp_policy");
    if (policy && !policy(env))
        abort();
    return setjmp(env);
}

#include <stdio.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setlinebuf_wrapper(FILE *stream)
{
    typedef bool (*policy_fn_t)(FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setlinebuf_policy");
    if (policy && !policy(stream))
        abort();
    setlinebuf(stream);
}

#include <locale.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *setlocale_wrapper(int category, const char *locale)
{
    typedef bool (*policy_fn_t)(int category, const char *locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setlocale_policy");
    if (policy && !policy(category, locale))
        abort();
    return setlocale(category, locale);
}

#include <syslog.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setlogmask_wrapper(int mask)
{
    typedef bool (*policy_fn_t)(int mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setlogmask_policy");
    if (policy && !policy(mask))
        abort();
    return setlogmask(mask);
}

#include <stdio.h>
#include <mntent.h>
#include <mntent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *setmntent_wrapper(const char *filename, const char *type)
{
    typedef bool (*policy_fn_t)(const char *filename, const char *type);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setmntent_policy");
    if (policy && !policy(filename, type))
        abort();
    return setmntent(filename, type);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setnetent_wrapper(int stayopen)
{
    typedef bool (*policy_fn_t)(int stayopen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setnetent_policy");
    if (policy && !policy(stayopen))
        abort();
    setnetent(stayopen);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setnetgrent_wrapper(const char *netgroup)
{
    typedef bool (*policy_fn_t)(const char *netgroup);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setnetgrent_policy");
    if (policy && !policy(netgroup))
        abort();
    return setnetgrent(netgroup);
}

#include <sched.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setns_wrapper(int fd, int nstype)
{
    typedef bool (*policy_fn_t)(int fd, int nstype);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setns_policy");
    if (policy && !policy(fd, nstype))
        abort();
    return setns(fd, nstype);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setpgid_wrapper(pid_t pid, pid_t pgid)
{
    typedef bool (*policy_fn_t)(pid_t pid, pid_t pgid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setpgid_policy");
    if (policy && !policy(pid, pgid))
        abort();
    return setpgid(pid, pgid);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setpgrp_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setpgrp_policy");
    if (policy && !policy())
        abort();
    return setpgrp();
}

#include <sys/time.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setpriority_wrapper(int which, id_t who, int prio)
{
    typedef bool (*policy_fn_t)(int which, id_t who, int prio);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setpriority_policy");
    if (policy && !policy(which, who, prio))
        abort();
    return setpriority(which, who, prio);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setprotoent_wrapper(int stayopen)
{
    typedef bool (*policy_fn_t)(int stayopen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setprotoent_policy");
    if (policy && !policy(stayopen))
        abort();
    setprotoent(stayopen);
}

#include <sys/types.h>
#include <pwd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setpwent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setpwent_policy");
    if (policy && !policy())
        abort();
    setpwent();
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setregid_wrapper(gid_t rgid, gid_t egid)
{
    typedef bool (*policy_fn_t)(gid_t rgid, gid_t egid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setregid_policy");
    if (policy && !policy(rgid, egid))
        abort();
    return setregid(rgid, egid);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setresgid_wrapper(gid_t rgid, gid_t egid, gid_t sgid)
{
    typedef bool (*policy_fn_t)(gid_t rgid, gid_t egid, gid_t sgid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setresgid_policy");
    if (policy && !policy(rgid, egid, sgid))
        abort();
    return setresgid(rgid, egid, sgid);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setresuid_wrapper(uid_t ruid, uid_t euid, uid_t suid)
{
    typedef bool (*policy_fn_t)(uid_t ruid, uid_t euid, uid_t suid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setresuid_policy");
    if (policy && !policy(ruid, euid, suid))
        abort();
    return setresuid(ruid, euid, suid);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setreuid_wrapper(uid_t ruid, uid_t euid)
{
    typedef bool (*policy_fn_t)(uid_t ruid, uid_t euid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setreuid_policy");
    if (policy && !policy(ruid, euid))
        abort();
    return setreuid(ruid, euid);
}

#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setrlimit_wrapper(int resource, const struct rlimit *rlim)
{
    typedef bool (*policy_fn_t)(int resource, const struct rlimit *rlim);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setrlimit_policy");
    if (policy && !policy(resource, rlim))
        abort();
    return setrlimit(resource, rlim);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setrpcent_wrapper(int stayopen)
{
    typedef bool (*policy_fn_t)(int stayopen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setrpcent_policy");
    if (policy && !policy(stayopen))
        abort();
    setrpcent(stayopen);
}

#include <netdb.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setservent_wrapper(int stayopen)
{
    typedef bool (*policy_fn_t)(int stayopen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setservent_policy");
    if (policy && !policy(stayopen))
        abort();
    setservent(stayopen);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t setsid_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setsid_policy");
    if (policy && !policy())
        abort();
    return setsid();
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setsockopt_wrapper(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    //wakka printffrom setsockopt\n");
    typedef bool (*policy_fn_t)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setsockopt_policy");
    if (policy && !policy(sockfd, level, optname, optval, optlen))
        abort();
    return setsockopt(sockfd, level, optname, optval, optlen);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setspent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setspent_policy");
    if (policy && !policy())
        abort();
    setspent();
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *setstate_wrapper(char *state)
{
    typedef bool (*policy_fn_t)(char *state);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setstate_policy");
    if (policy && !policy(state))
        abort();
    return setstate(state);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setstate_r_wrapper(char *statebuf, struct random_data *buf)
{
    typedef bool (*policy_fn_t)(char *statebuf, struct random_data *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setstate_r_policy");
    if (policy && !policy(statebuf, buf))
        abort();
    return setstate_r(statebuf, buf);
}

#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int settimeofday_wrapper(const struct timeval *tv, const struct timezone *tz)
{
    typedef bool (*policy_fn_t)(const struct timeval *tv, const struct timezone *tz);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "settimeofday_policy");
    if (policy && !policy(tv, tz))
        abort();
    return settimeofday(tv, tz);
}

#include <ttyent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setttyent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setttyent_policy");
    if (policy && !policy())
        abort();
    return setttyent();
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setuid_wrapper(uid_t uid)
{
    typedef bool (*policy_fn_t)(uid_t uid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setuid_policy");
    if (policy && !policy(uid))
        abort();
    return setuid(uid);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setusershell_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setusershell_policy");
    if (policy && !policy())
        abort();
    setusershell();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setutent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setutent_policy");
    if (policy && !policy())
        abort();
    setutent();
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void setutxent_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setutxent_policy");
    if (policy && !policy())
        abort();
    setutxent();
}

#include <stdio.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setvbuf_wrapper(FILE *stream, char *buf, int mode, size_t size)
{
    typedef bool (*policy_fn_t)(FILE *stream, char *buf, int mode, size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setvbuf_policy");
    if (policy && !policy(stream, buf, mode, size))
        abort();
    return setvbuf(stream, buf, mode, size);
}

#include <sys/types.h>
#include <sys/xattr.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int setxattr_wrapper(const char *path, const char *name, const void *value, size_t size, int flags)
{
    typedef bool (*policy_fn_t)(const char *path, const char *name, const void *value, size_t size, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "setxattr_policy");
    if (policy && !policy(path, name, value, size, flags))
        abort();
    return setxattr(path, name, value, size, flags);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

struct spwd *sgetspent_wrapper(const char *s)
{
    typedef bool (*policy_fn_t)(const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sgetspent_policy");
    if (policy && !policy(s))
        abort();
    return sgetspent(s);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sgetspent_r_wrapper(const char *s, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp)
{
    typedef bool (*policy_fn_t)(const char *s, struct spwd *spbuf, char *buf, size_t buflen, struct spwd **spbufp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sgetspent_r_policy");
    if (policy && !policy(s, spbuf, buf, buflen, spbufp))
        abort();
    return sgetspent_r(s, spbuf, buf, buflen, spbufp);
}

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int shm_open_wrapper(const char *name, int oflag, mode_t mode)
{
    typedef bool (*policy_fn_t)(const char *name, int oflag, mode_t mode);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shm_open_policy");
    if (policy && !policy(name, oflag, mode))
        abort();
    return shm_open(name, oflag, mode);
}

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int shm_unlink_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shm_unlink_policy");
    if (policy && !policy(name))
        abort();
    return shm_unlink(name);
}

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *shmat_wrapper(int shmid, const void *shmaddr, int shmflg)
{
    //wakka printffrom shmat\n");
    typedef bool (*policy_fn_t)(int shmid, const void *shmaddr, int shmflg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shmat_policy");
    if (policy && !policy(shmid, shmaddr, shmflg))
        abort();
    return shmat(shmid, shmaddr, shmflg);
}

#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int shmctl_wrapper(int shmid, int cmd, struct shmid_ds *buf)
{
    typedef bool (*policy_fn_t)(int shmid, int cmd, struct shmid_ds *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shmctl_policy");
    if (policy && !policy(shmid, cmd, buf))
        abort();
    return shmctl(shmid, cmd, buf);
}

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int shmdt_wrapper(const void *shmaddr)
{
    typedef bool (*policy_fn_t)(const void *shmaddr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shmdt_policy");
    if (policy && !policy(shmaddr))
        abort();
    return shmdt(shmaddr);
}

#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int shmget_wrapper(key_t key, size_t size, int shmflg)
{
    //wakka printffrom shmget\n");
    typedef bool (*policy_fn_t)(key_t key, size_t size, int shmflg);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shmget_policy");
    if (policy && !policy(key, size, shmflg))
        abort();
    return shmget(key, size, shmflg);
}

#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int shutdown_wrapper(int sockfd, int how)
{
    //wakka printffrom shutdown\n");
    typedef bool (*policy_fn_t)(int sockfd, int how);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "shutdown_policy");
    if (policy && !policy(sockfd, how))
        abort();
    return shutdown(sockfd, how);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *sigabbrev_np_wrapper(int sig)
{
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "sigabbrev_np_policy");

    if (policy && !policy(sig))
        abort();

    return sigabbrev_np(sig);
}


#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigaction_wrapper(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    //wakka printffrom sigaction\n");
    fprintf(stdout, "[sigaction] signum=%d\n", signum);
    if (signum == SIGPIPE && act)
    {
        fprintf(stderr, "[sigaction-policy] SIGPIPE handler set (flags=0x%x)\n", act->sa_flags);
    }

    typedef bool (*policy_fn_t)(int signum, const struct sigaction *act, struct sigaction *oldact);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigaction_policy");
    if (policy && !policy(signum, act, oldact))
        abort();
    return sigaction(signum, act, oldact);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigaddset_wrapper(sigset_t *set, int signum)
{
    typedef bool (*policy_fn_t)(sigset_t *set, int signum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigaddset_policy");
    if (policy && !policy(set, signum))
        abort();
    return sigaddset(set, signum);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigaltstack_wrapper(const stack_t *ss, stack_t *old_ss)
{
    typedef bool (*policy_fn_t)(const stack_t *ss, stack_t *old_ss);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigaltstack_policy");
    if (policy && !policy(ss, old_ss))
        abort();
    return sigaltstack(ss, old_ss);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigandset_wrapper(sigset_t *dest, const sigset_t *left, const sigset_t *right)
{
    typedef bool (*policy_fn_t)(sigset_t *dest, const sigset_t *left, const sigset_t *right);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigandset_policy");
    if (policy && !policy(dest, left, right))
        abort();
    return sigandset(dest, left, right);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigblock_wrapper(int mask)
{
    typedef bool (*policy_fn_t)(int mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigblock_policy");
    if (policy && !policy(mask))
        abort();
    return sigblock(mask);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigdelset_wrapper(sigset_t *set, int signum)
{
    typedef bool (*policy_fn_t)(sigset_t *set, int signum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigdelset_policy");
    if (policy && !policy(set, signum))
        abort();
    return sigdelset(set, signum);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *sigdescr_np_wrapper(int sig)
{
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "sigdescr_np_policy");

    if (policy && !policy(sig))
        abort();

    return const_cast<char *>(sigdescr_np(sig));
}


#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigemptyset_wrapper(sigset_t *set)
{
    typedef bool (*policy_fn_t)(sigset_t *set);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigemptyset_policy");
    if (policy && !policy(set))
        abort();
    return sigemptyset(set);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigfillset_wrapper(sigset_t *set)
{
    typedef bool (*policy_fn_t)(sigset_t *set);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigfillset_policy");
    if (policy && !policy(set))
        abort();
    return sigfillset(set);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int siggetmask_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "siggetmask_policy");
    if (policy && !policy())
        abort();
    return siggetmask();
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sighold_wrapper(int sig)
{
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sighold_policy");
    if (policy && !policy(sig))
        abort();
    return sighold(sig);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigignore_wrapper(int sig)
{
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigignore_policy");
    if (policy && !policy(sig))
        abort();
    return sigignore(sig);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int siginterrupt_wrapper(int sig, int flag)
{
    typedef bool (*policy_fn_t)(int sig, int flag);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "siginterrupt_policy");
    if (policy && !policy(sig, flag))
        abort();
    return siginterrupt(sig, flag);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigisemptyset_wrapper(const sigset_t *set)
{
    typedef bool (*policy_fn_t)(const sigset_t *set);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigisemptyset_policy");
    if (policy && !policy(set))
        abort();
    return sigisemptyset(set);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigismember_wrapper(const sigset_t *set, int signum)
{
    typedef bool (*policy_fn_t)(const sigset_t *set, int signum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigismember_policy");
    if (policy && !policy(set, signum))
        abort();
    return sigismember(set, signum);
}

#include <setjmp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void siglongjmp_wrapper(sigjmp_buf env, int val)
{
    typedef bool (*policy_fn_t)(sigjmp_buf env, int val);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "siglongjmp_policy");
    if (policy && !policy(env, val))
        abort();
    siglongjmp(env, val);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

sighandler_t signal_wrapper(int signum, sighandler_t handler)
{
    //wakka printffrom signal\n");
    typedef bool (*policy_fn_t)(int signum, sighandler_t handler);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "signal_policy");
    if (policy && !policy(signum, handler))
        abort();
    return signal(signum, handler);
}

#include <sys/signalfd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int signalfd_wrapper(int fd, const sigset_t *mask, int flags)
{
    typedef bool (*policy_fn_t)(int fd, const sigset_t *mask, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "signalfd_policy");
    if (policy && !policy(fd, mask, flags))
        abort();
    return signalfd(fd, mask, flags);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigorset_wrapper(sigset_t *dest, const sigset_t *left, const sigset_t *right)
{
    typedef bool (*policy_fn_t)(sigset_t *dest, const sigset_t *left, const sigset_t *right);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigorset_policy");
    if (policy && !policy(dest, left, right))
        abort();
    return sigorset(dest, left, right);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigpause_wrapper(int sigmask)
{
    typedef bool (*policy_fn_t)(int sigmask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigpause_policy");
    if (policy && !policy(sigmask))
        abort();
    return sigpause(sigmask);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigpending_wrapper(sigset_t *set)
{
    typedef bool (*policy_fn_t)(sigset_t *set);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigpending_policy");
    if (policy && !policy(set))
        abort();
    return sigpending(set);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigprocmask_wrapper(int how, const sigset_t *set, sigset_t *oldset)
{
    //wakka printffrom sigprocmask\n");
    typedef bool (*policy_fn_t)(int how, const sigset_t *set, sigset_t *oldset);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigprocmask_policy");
    if (policy && !policy(how, set, oldset))
        abort();
    return sigprocmask(how, set, oldset);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigqueue_wrapper(pid_t pid, int sig, const union sigval value)
{
    typedef bool (*policy_fn_t)(pid_t pid, int sig, const union sigval value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigqueue_policy");
    if (policy && !policy(pid, sig, value))
        abort();
    return sigqueue(pid, sig, value);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigrelse_wrapper(int sig)
{
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigrelse_policy");
    if (policy && !policy(sig))
        abort();
    return sigrelse(sig);
}

// #include <signal.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// long sigreturn_wrapper(void) {
//     typedef bool (*policy_fn_t)(void);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigreturn_policy");
//     if(policy && !policy()) abort();
//     return sigreturn();
// }

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

sighandler_t sigset_wrapper(int sig, sighandler_t disp)
{
    typedef bool (*policy_fn_t)(int sig, sighandler_t disp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigset_policy");
    if (policy && !policy(sig, disp))
        abort();
    return sigset(sig, disp);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigsetmask_wrapper(int mask)
{
    typedef bool (*policy_fn_t)(int mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigsetmask_policy");
    if (policy && !policy(mask))
        abort();
    return sigsetmask(mask);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigstack_wrapper(struct sigstack *ss, struct sigstack *oss)
{
    typedef bool (*policy_fn_t)(struct sigstack *ss, struct sigstack *oss);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigstack_policy");
    if (policy && !policy(ss, oss))
        abort();
    return sigstack(ss, oss);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigsuspend_wrapper(const sigset_t *mask)
{
    typedef bool (*policy_fn_t)(const sigset_t *mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigsuspend_policy");
    if (policy && !policy(mask))
        abort();
    return sigsuspend(mask);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigtimedwait_wrapper(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)
{
    typedef bool (*policy_fn_t)(const sigset_t *set, siginfo_t *info, const struct timespec *timeout);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigtimedwait_policy");
    if (policy && !policy(set, info, timeout))
        abort();
    return sigtimedwait(set, info, timeout);
}

// #include <signal.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int sigvec_wrapper(int sig, const struct sigvec *vec, struct sigvec *ovec)
// {
//     typedef bool (*policy_fn_t)(int sig, const struct sigvec *vec, struct sigvec *ovec);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigvec_policy");
//     if (policy && !policy(sig, vec, ovec))
//         abort();
//     return sigvec(sig, vec, ovec);
// }

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigwait_wrapper(const sigset_t *set, int *sig)
{
    typedef bool (*policy_fn_t)(const sigset_t *set, int *sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigwait_policy");
    if (policy && !policy(set, sig))
        abort();
    return sigwait(set, sig);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sigwaitinfo_wrapper(const sigset_t *set, siginfo_t *info)
{
    typedef bool (*policy_fn_t)(const sigset_t *set, siginfo_t *info);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sigwaitinfo_policy");
    if (policy && !policy(set, info))
        abort();
    return sigwaitinfo(set, info);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned int sleep_wrapper(unsigned int seconds)
{
    typedef bool (*policy_fn_t)(unsigned int seconds);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sleep_policy");
    if (policy && !policy(seconds))
        abort();
    return sleep(seconds);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int snprintf_wrapper(char *str, size_t size, const char *format, ...)
{
    //wakka printfhello from snprintfy %s\n", str);
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(char *str, size_t size, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "snprintf_policy");
    if (policy && !policy(str, size, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vsnprintf(str, size, format, args);
    va_end(args);
    //wakka printfend\n");
    return ret;
}

#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sockatmark_wrapper(int sockfd)
{
    typedef bool (*policy_fn_t)(int sockfd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sockatmark_policy");
    if (policy && !policy(sockfd))
        abort();
    return sockatmark(sockfd);
}

#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int socket_wrapper(int domain, int type, int protocol)
{
    FILE *log = fopen("socket.txt", "a");
    if (log != NULL)
    {
        fprintf(log, "from socket\n");
        fprintf(log, "domain : %d  type = %d  protocol = %d\n", domain, type, protocol);
        fclose(log);
    }

    typedef bool (*policy_fn_t)(int domain, int type, int protocol);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "socket_policy");
    if (policy && !policy(domain, type, protocol))
        abort();
    return socket(domain, type, protocol);
}



#include <sys/types.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>
int socketpair_wrapper(int domain, int type, int protocol, int sv[2])
{
    //wakka printffrom socketpair \n");
    //wakka printfdomain : %d  type : %d  protocol = %d  sv[0] = %d  sv[1] = %d\n",   domain, type, protocol, sv[0], sv[1]);

    typedef bool (*policy_fn_t)(int, int, int, int sv[2]);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "socketpair_policy");

    if (policy && !policy(domain, type, protocol, sv))
        abort();

    return socketpair(domain, type, protocol, sv);
}


#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t splice_wrapper(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
{
    typedef bool (*policy_fn_t)(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "splice_policy");
    if (policy && !policy(fd_in, off_in, fd_out, off_out, len, flags))
        abort();
    return splice(fd_in, off_in, fd_out, off_out, len, flags);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sprintf_wrapper(char *str, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(char *str, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sprintf_policy");
    if (policy && !policy(str, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vsprintf(str, format, args);
    va_end(args);
    return ret;
}

#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void srand_wrapper(unsigned int seed)
{
    typedef bool (*policy_fn_t)(unsigned int seed);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "srand_policy");
    if (policy && !policy(seed))
        abort();
    srand(seed);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void srand48_wrapper(long seedval)
{
    typedef bool (*policy_fn_t)(long seedval);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "srand48_policy");
    if (policy && !policy(seedval))
        abort();
    srand48(seedval);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int srand48_r_wrapper(long int seedval, struct drand48_data *buffer)
{
    typedef bool (*policy_fn_t)(long int seedval, struct drand48_data *buffer);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "srand48_r_policy");
    if (policy && !policy(seedval, buffer))
        abort();
    return srand48_r(seedval, buffer);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void srandom_wrapper(unsigned seed)
{
    typedef bool (*policy_fn_t)(unsigned seed);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "srandom_policy");
    if (policy && !policy(seed))
        abort();
    srandom(seed);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int srandom_r_wrapper(unsigned int seed, struct random_data *buf)
{
    typedef bool (*policy_fn_t)(unsigned int seed, struct random_data *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "srandom_r_policy");
    if (policy && !policy(seed, buf))
        abort();
    return srandom_r(seed, buf);
}

#include <stdio.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sscanf_wrapper(const char *str, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(const char *str, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sscanf_policy");
    if (policy && !policy(str, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vsscanf(str, format, args);
    va_end(args);
    return ret;
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

sighandler_t ssignal_wrapper(int signum, sighandler_t action)
{
    typedef bool (*policy_fn_t)(int signum, sighandler_t action);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ssignal_policy");
    if (policy && !policy(signum, action))
        abort();
    return ssignal(signum, action);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int stat_wrapper(const char *pathname, struct stat *statbuf)
{
    typedef bool (*policy_fn_t)(const char *pathname, struct stat *statbuf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "stat_policy");
    if (policy && !policy(pathname, statbuf))
        abort();
    return stat(pathname, statbuf);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int stat64_wrapper(const char *pathname, struct stat *statbuf)
{
    typedef bool (*policy_fn_t)(const char *, struct stat *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "stat64_policy");
    if (policy && !policy(pathname, statbuf))
        abort();

    return stat(pathname, statbuf);   // modern syscall
}

#include <sys/vfs.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int statfs_wrapper(const char *path, struct statfs *buf)
{
    typedef bool (*policy_fn_t)(const char *path, struct statfs *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "statfs_policy");
    if (policy && !policy(path, buf))
        abort();
    return statfs(path, buf);
}

#include <sys/vfs.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int statfs64_wrapper(const char *path, struct statfs *buf)
{
    typedef bool (*policy_fn_t)(const char *, struct statfs *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "statfs64_policy");
    if (policy && !policy(path, buf))
        abort();

    return statfs(path, buf);  // <— switch from statfs64
}


#include <sys/statvfs.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int statvfs_wrapper(const char *path, struct statvfs *buf)
{
    typedef bool (*policy_fn_t)(const char *path, struct statvfs *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "statvfs_policy");
    if (policy && !policy(path, buf))
        abort();
    return statvfs(path, buf);
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int statx_wrapper(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "statx_policy");
    if (policy && !policy(dirfd, pathname, flags, mask, statxbuf))
        abort();
    return statx(dirfd, pathname, flags, mask, statxbuf);
}

// #include <time.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int stime_wrapper(const time_t *t)
// {
//     typedef bool (*policy_fn_t)(const time_t *t);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "stime_policy");
//     if (policy && !policy(t))
//         abort();
//     return stime(t);
// }

#include <string.h>
#include <string.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *stpcpy_wrapper(char *dest, const char *src)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "stpcpy_policy");
    if (policy && !policy(dest, src))
        abort();
    return stpcpy(dest, src);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *stpncpy_wrapper(char *dest, const char *src, size_t n)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "stpncpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return stpncpy(dest, src, n);
}

#include <strings.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strcasecmp_wrapper(const char *s1, const char *s2)
{
    typedef bool (*policy_fn_t)(const char *s1, const char *s2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strcasecmp_policy");
    if (policy && !policy(s1, s2))
        abort();
    return strcasecmp(s1, s2);
}

#include <string.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strcasestr_wrapper(const char *haystack, const char *needle)
{
    typedef bool (*policy_fn_t)(const char *, const char *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strcasestr_policy");

    if (policy && !policy(haystack, needle))
        abort();

    return const_cast<char *>(strcasestr(haystack, needle));
}


#include <string.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strcat_wrapper(char *dest, const char *src)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strcat_policy");
    if (policy && !policy(dest, src))
        abort();
    return strcat(dest, src);
}

#include <string.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strchr_wrapper(const char *s, int c)
{
    typedef bool (*policy_fn_t)(const char *, int);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strchr_policy");

    if (policy && !policy(s, c))
        abort();

    return const_cast<char *>(strchr(s, c));
}

#include <string.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strchrnul_wrapper(const char *s, int c)
{
    typedef bool (*policy_fn_t)(const char *, int);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strchrnul_policy");

    if (policy && !policy(s, c))
        abort();

    return const_cast<char *>(strchrnul(s, c));
}


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strcmp_wrapper(const char *s1, const char *s2)
{
    typedef bool (*policy_fn_t)(const char *s1, const char *s2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strcmp_policy");
    if (policy && !policy(s1, s2))
        abort();
    return strcmp(s1, s2);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strcoll_wrapper(const char *s1, const char *s2)
{
    typedef bool (*policy_fn_t)(const char *s1, const char *s2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strcoll_policy");
    if (policy && !policy(s1, s2))
        abort();
    return strcoll(s1, s2);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strcpy_wrapper(char *dest, const char *src)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strcpy_policy");
    if (policy && !policy(dest, src))
        abort();
    return strcpy(dest, src);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t strcspn_wrapper(const char *s, const char *reject)
{
    typedef bool (*policy_fn_t)(const char *s, const char *reject);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strcspn_policy");
    if (policy && !policy(s, reject))
        abort();
    return strcspn(s, reject);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strdup_wrapper(const char *s)
{
    typedef bool (*policy_fn_t)(const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strdup_policy");
    if (policy && !policy(s))
        abort();
    return strdup(s);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strerror_wrapper(int errnum)
{
    typedef bool (*policy_fn_t)(int);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strerror_policy");

    if (policy && !policy(errnum))
        abort();

    return const_cast<char *>(strerror(errnum));
}


#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strerror_l_wrapper(int errnum, locale_t locale)
{
    typedef bool (*policy_fn_t)(int errnum, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strerror_l_policy");
    if (policy && !policy(errnum, locale))
        abort();
    return strerror_l(errnum, locale);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strerror_r_wrapper(int errnum, char *buf, size_t buflen)
{
    typedef bool (*policy_fn_t)(int, char*, size_t);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strerror_r_policy");

    if (policy && !policy(errnum, buf, buflen))
        abort();

    // GNU strerror_r returns char*
    char *msg = strerror_r(errnum, buf, buflen);

    if (msg != buf && msg != nullptr) {
        strncpy(buf, msg, buflen - 1);
        buf[buflen - 1] = '\0';
    }

    return 0;
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *strerrordesc_np_wrapper(int errnum)
{
    typedef bool (*policy_fn_t)(int errnum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strerrordesc_np_policy");
    if (policy && !policy(errnum))
        abort();
    return strerrordesc_np(errnum);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

const char *strerrorname_np_wrapper(int errnum)
{
    typedef bool (*policy_fn_t)(int errnum);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strerrorname_np_policy");
    if (policy && !policy(errnum))
        abort();
    return strerrorname_np(errnum);
}

#include <monetary.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t strfmon_wrapper(char *s, size_t max, const char *format, ...)
{
}

#include <monetary.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t strfmon_l_wrapper(char *s, size_t max, locale_t locale, const char *format, ...)
{
}

// #include <stdlib.h>
// #include <stdlib.h>
// #include <stdlib.h>
// #include <stdlib.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int strerror_r_wrapper(int errnum, char *buf, size_t buflen)
// {
//     typedef bool (*policy_fn_t)(int, char*, size_t);
//     policy_fn_t policy =
//         (policy_fn_t)dlsym(RTLD_NEXT, "strerror_r_policy");

//     if (policy && !policy(errnum, buf, buflen))
//         abort();

//     // GNU strerror_r returns char*
//     char *msg = strerror_r(errnum, buf, buflen);

//     // If returned pointer isn't our buffer, copy it
//     if (msg != buf && msg != nullptr) {
//         strncpy(buf, msg, buflen - 1);
//         buf[buflen - 1] = '\0';
//     }

//     return 0;
// }


#include <stdlib.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strfromf_wrapper(char *str, size_t n, const char *format, float fp)
{
    typedef bool (*policy_fn_t)(char *, size_t, const char *, float);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strfromf_policy");

    if (policy && !policy(str, n, format, fp))
        abort();

    return strfromf(str, n, format, fp);
}

#include <stdlib.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strfroml_wrapper(char *str, size_t n, const char *format, long double fp)
{
    typedef bool (*policy_fn_t)(char *, size_t, const char *, long double);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strfroml_policy");

    if (policy && !policy(str, n, format, fp))
        abort();

    return strfroml(str, n, format, fp);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strfry_wrapper(char *string)
{
    typedef bool (*policy_fn_t)(char *string);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strfry_policy");
    if (policy && !policy(string))
        abort();
    return strfry(string);
}

#include <time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t strftime_wrapper(char *s, size_t max, const char *format, const struct tm *tm)
{
    typedef bool (*policy_fn_t)(char *s, size_t max, const char *format, const struct tm *tm);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strftime_policy");
    if (policy && !policy(s, max, format, tm))
        abort();
    return strftime(s, max, format, tm);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t strlen_wrapper(const char *s)
{
    typedef bool (*policy_fn_t)(const char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strlen_policy");
    if (policy && !policy(s))
        abort();
    return strlen(s);
}

#include <strings.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strncasecmp_wrapper(const char *s1, const char *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const char *s1, const char *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strncasecmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return strncasecmp(s1, s2, n);
}

#include <string.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strncat_wrapper(char *dest, const char *src, size_t n)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strncat_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return strncat(dest, src, n);
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strncmp_wrapper(const char *s1, const char *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const char *s1, const char *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strncmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return strncmp(s1, s2, n);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strncpy_wrapper(char *dest, const char *src, size_t n)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strncpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return strncpy(dest, src, n);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strndup_wrapper(const char *s, size_t n)
{
    typedef bool (*policy_fn_t)(const char *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strndup_policy");
    if (policy && !policy(s, n))
        abort();
    return strndup(s, n);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t strnlen_wrapper(const char *s, size_t maxlen)
{
    typedef bool (*policy_fn_t)(const char *s, size_t maxlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strnlen_policy");
    if (policy && !policy(s, maxlen))
        abort();
    return strnlen(s, maxlen);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strpbrk_wrapper(const char *s, const char *accept)
{
    typedef bool (*policy_fn_t)(const char *, const char *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strpbrk_policy");

    if (policy && !policy(s, accept))
        abort();

    return const_cast<char *>(strpbrk(s, accept));
}


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strptime_wrapper(const char *s, const char *format, struct tm *tm)
{
    typedef bool (*policy_fn_t)(const char *s, const char *format, struct tm *tm);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strptime_policy");
    if (policy && !policy(s, format, tm))
        abort();
    return strptime(s, format, tm);
}

#include <string.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strstr_wrapper(const char *haystack, const char *needle)
{
    typedef bool (*policy_fn_t)(const char *, const char *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "strstr_policy");

    if (policy && !policy(haystack, needle))
        abort();

    return const_cast<char *>(strstr(haystack, needle));
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strsep_wrapper(char **stringp, const char *delim)
{
    typedef bool (*policy_fn_t)(char **stringp, const char *delim);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strsep_policy");
    if (policy && !policy(stringp, delim))
        abort();
    return strsep(stringp, delim);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strsignal_wrapper(int sig)
{
    typedef bool (*policy_fn_t)(int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strsignal_policy");
    if (policy && !policy(sig))
        abort();
    return strsignal(sig);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t strspn_wrapper(const char *s, const char *accept)
{
    typedef bool (*policy_fn_t)(const char *s, const char *accept);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strspn_policy");
    if (policy && !policy(s, accept))
        abort();
    return strspn(s, accept);
}

// #include <string.h>
// #include <string.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// char *strstr_wrapper(const char *haystack, const char *needle)
// {
//     typedef bool (*policy_fn_t)(const char *, const char *);
//     policy_fn_t policy =
//         (policy_fn_t)dlsym(RTLD_NEXT, "strstr_policy");

//     if (policy && !policy(haystack, needle))
//         abort();

//     return const_cast<char *>(strstr(haystack, needle));
// }


#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

double strtod_wrapper(const char *nptr, char **endptr)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtod_policy");
    if (policy && !policy(nptr, endptr))
        abort();
    return strtod(nptr, endptr);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

float strtof_wrapper(const char *nptr, char **endptr)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtof_policy");
    if (policy && !policy(nptr, endptr))
        abort();
    return strtof(nptr, endptr);
}

#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

intmax_t strtoimax_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtoimax_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtoimax(nptr, endptr, base);
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strtok_wrapper(char *str, const char *delim)
{
    typedef bool (*policy_fn_t)(char *str, const char *delim);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtok_policy");
    if (policy && !policy(str, delim))
        abort();
    return strtok(str, delim);
}

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *strtok_r_wrapper(char *str, const char *delim, char **saveptr)
{
    typedef bool (*policy_fn_t)(char *str, const char *delim, char **saveptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtok_r_policy");
    if (policy && !policy(str, delim, saveptr))
        abort();
    return strtok_r(str, delim, saveptr);
}

#include <stdlib.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long strtol_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtol_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtol(nptr, endptr, base);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long double strtold_wrapper(const char *nptr, char **endptr)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtold_policy");
    if (policy && !policy(nptr, endptr))
        abort();
    return strtold(nptr, endptr);
}

#include <stdlib.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long long strtoll_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtoll_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtoll(nptr, endptr, base);
}

#include <stdlib.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

quad_t strtoq_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtoq_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtoq(nptr, endptr, base);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned long strtoul_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtoul_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtoul(nptr, endptr, base);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

unsigned long long strtoull_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtoull_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtoull(nptr, endptr, base);
}

#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uintmax_t strtoumax_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtoumax_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtoumax(nptr, endptr, base);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

u_quad_t strtouq_wrapper(const char *nptr, char **endptr, int base)
{
    typedef bool (*policy_fn_t)(const char *nptr, char **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strtouq_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return strtouq(nptr, endptr, base);
}

#include <string.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int strverscmp_wrapper(const char *s1, const char *s2)
{
    typedef bool (*policy_fn_t)(const char *s1, const char *s2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strverscmp_policy");
    if (policy && !policy(s1, s2))
        abort();
    return strverscmp(s1, s2);
}

#include <string.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t strxfrm_wrapper(char *dest, const char *src, size_t n)
{
    typedef bool (*policy_fn_t)(char *dest, const char *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "strxfrm_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return strxfrm(dest, src, n);
}

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svc_exit_wrapper(void)
// {
//     typedef bool (*policy_fn_t)(void);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_exit_policy");
//     if (policy && !policy())
//         abort();
//     svc_exit();
// }

// // #include <rpc/rpc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void __wrapper(int rdfds)
// {
//     typedef bool (*policy_fn_t)(int rdfds);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_getreq_policy");
//     if (policy && !policy(rdfds))
//         abort();
//     svc_getreq(rdfds);
// }

// // #include <rpc/rpc.h>
//// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svc_getreq_common_wrapper(const int fd)
// {
//     typedef bool (*policy_fn_t)(const int fd);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_getreq_common_policy");
//     if (policy && !policy(fd))
//         abort();
//     svc_getreq_common(fd);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svc_getreq_poll_wrapper(struct pollfd *pfdp, const int pollretval)
// {
//     typedef bool (*policy_fn_t)(struct pollfd *pfdp, const int pollretval);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_getreq_poll_policy");
//     if (policy && !policy(pfdp, pollretval))
//         abort();
//     svc_getreq_poll(pfdp, pollretval);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svc_getreqset_wrapper(fd_set *rdfds)
// {
//     typedef bool (*policy_fn_t)(fd_set *rdfds);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_getreqset_policy");
//     if (policy && !policy(rdfds))
//         abort();
//     svc_getreqset(rdfds);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svc_run_wrapper(void)
// {
//     typedef bool (*policy_fn_t)(void);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_run_policy");
//     if (policy && !policy())
//         abort();
//     svc_run();
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// bool_t svc_sendreply_wrapper(SVCXPRT *xprt, xdrproc_t outproc, char *out)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt, xdrproc_t outproc, char *out);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_sendreply_policy");
//     if (policy && !policy(xprt, outproc, out))
//         abort();
//     return svc_sendreply(xprt, outproc, out);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svc_unregister_wrapper(unsigned long prognum, unsigned long versnum)
// {
//     typedef bool (*policy_fn_t)(unsigned long prognum, unsigned long versnum);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svc_unregister_policy");
//     if (policy && !policy(prognum, versnum))
//         abort();
//     svc_unregister(prognum, versnum);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_auth_wrapper(SVCXPRT *xprt, enum auth_stat why)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt, enum auth_stat why);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_auth_policy");
//     if (policy && !policy(xprt, why))
//         abort();
//     svcerr_auth(xprt, why);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_decode_wrapper(SVCXPRT *xprt)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_decode_policy");
//     if (policy && !policy(xprt))
//         abort();
//     svcerr_decode(xprt);
// }

// // #include <rpc/rpc.h>
// #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_noproc_wrapper(SVCXPRT *xprt)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_noproc_policy");
//     if (policy && !policy(xprt))
//         abort();
//     svcerr_noproc(xprt);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_noprog_wrapper(SVCXPRT *xprt)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_noprog_policy");
//     if (policy && !policy(xprt))
//         abort();
//     svcerr_noprog(xprt);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_progvers_wrapper(SVCXPRT *xprt, u_long lowvers, u_long highvers)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt, u_long, u_long);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_progvers_policy");
//     if (policy && !policy(xprt, lowvers, highvers))
//         abort();
//     svcerr_progvers(xprt, lowvers, highvers);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_systemerr_wrapper(SVCXPRT *xprt)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_systemerr_policy");
//     if (policy && !policy(xprt))
//         abort();
//     svcerr_systemerr(xprt);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// void svcerr_weakauth_wrapper(SVCXPRT *xprt)
// {
//     typedef bool (*policy_fn_t)(SVCXPRT *xprt);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcerr_weakauth_policy");
//     if (policy && !policy(xprt))
//         abort();
//     svcerr_weakauth(xprt);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// SVCXPRT *svcfd_create_wrapper(int fd, unsigned int sendsize, unsigned int recvsize)
// {
//     typedef bool (*policy_fn_t)(int fd, unsigned int sendsize, unsigned int recvsize);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcfd_create_policy");
//     if (policy && !policy(fd, sendsize, recvsize))
//         abort();
//     return svcfd_create(fd, sendsize, recvsize);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// SVCXPRT *svcraw_create_wrapper(void)
// {
//     typedef bool (*policy_fn_t)(void);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcraw_create_policy");
//     if (policy && !policy())
//         abort();
//     return svcraw_create();
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// SVCXPRT *svctcp_create_wrapper(int sock, unsigned int send_buf_size, unsigned int recv_buf_size)
// {
//     typedef bool (*policy_fn_t)(int sock, unsigned int send_buf_size, unsigned int recv_buf_size);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svctcp_create_policy");
//     if (policy && !policy(sock, send_buf_size, recv_buf_size))
//         abort();
//     return svctcp_create(sock, send_buf_size, recv_buf_size);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// SVCXPRT *svcudp_bufcreate_wrapper(int sock, unsigned int sendsize, unsigned int recosize)
// {
//     typedef bool (*policy_fn_t)(int sock, unsigned int sendsize, unsigned int recosize);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcudp_bufcreate_policy");
//     if (policy && !policy(sock, sendsize, recosize))
//         abort();
//     return svcudp_bufcreate(sock, sendsize, recosize);
// }

// // // #include <rpc/rpc.h>
// // #include <rpc/svc.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// SVCXPRT *svcudp_create_wrapper(int sock)
// {
//     typedef bool (*policy_fn_t)(int sock);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "svcudp_create_policy");
//     if (policy && !policy(sock))
//         abort();
//     return svcudp_create(sock);
// }

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void swab_wrapper(const void *from, void *to, ssize_t n)
{
    typedef bool (*policy_fn_t)(const void *from, void *to, ssize_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "swab_policy");
    if (policy && !policy(from, to, n))
        abort();
    swab(from, to, n);
}

#include <ucontext.h>
#include <ucontext.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int swapcontext_wrapper(ucontext_t *oucp, const ucontext_t *ucp)
{
    //wakka printffrom swapcontext\n");
    typedef bool (*policy_fn_t)(ucontext_t *oucp, const ucontext_t *ucp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "swapcontext_policy");
    if (policy && !policy(oucp, ucp))
        abort();
    return swapcontext(oucp, ucp);
}

#include <unistd.h>
#include <sys/swap.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int swapoff_wrapper(const char *path)
{
    typedef bool (*policy_fn_t)(const char *path);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "swapoff_policy");
    if (policy && !policy(path))
        abort();
    return swapoff(path);
}

#include <unistd.h>
#include <sys/swap.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int swapon_wrapper(const char *path, int swapflags)
{
    typedef bool (*policy_fn_t)(const char *path, int swapflags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "swapon_policy");
    if (policy && !policy(path, swapflags))
        abort();
    return swapon(path, swapflags);
}

#include <wchar.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>

int swprintf_wrapper(wchar_t *wcs, size_t maxlen, const wchar_t *format, ...)
{
    va_list args;
    va_start(args, format);

    // Policy typedef: use correct types
    typedef bool (*policy_fn_t)(wchar_t *wcs, size_t maxlen, const wchar_t *format, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "swprintf_policy");
    if (policy && !policy(wcs, maxlen, format, args))
    {
        va_end(args);
        abort();
    }

    int ret = vswprintf(wcs, maxlen, format, args);
    va_end(args);
    return ret;
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int symlink_wrapper(const char *target, const char *linkpath)
{
    typedef bool (*policy_fn_t)(const char *target, const char *linkpath);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "symlink_policy");
    if (policy && !policy(target, linkpath))
        abort();
    return symlink(target, linkpath);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int symlinkat_wrapper(const char *target, int newdirfd, const char *linkpath)
{
    typedef bool (*policy_fn_t)(const char *target, int newdirfd, const char *linkpath);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "symlinkat_policy");
    if (policy && !policy(target, newdirfd, linkpath))
        abort();
    return symlinkat(target, newdirfd, linkpath);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void sync_wrapper(void)
{
    //wakka printffrom sync\n");
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sync_policy");
    if (policy && !policy())
        abort();
    sync();
}

#include <fcntl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sync_file_range_wrapper(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
    typedef bool (*policy_fn_t)(int fd, off64_t offset, off64_t nbytes, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sync_file_range_policy");
    if (policy && !policy(fd, offset, nbytes, flags))
        abort();
    return sync_file_range(fd, offset, nbytes, flags);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int syncfs_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "syncfs_policy");
    if (policy && !policy(fd))
        abort();
    return syncfs(fd);
}

#include <unistd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long syscall_wrapper(long number, ...)
{
    //wakka printfhello from syscall %ld\n", number);
    va_list args;
    va_start(args, number);
    long var_argv[10] = {0};
    for (int i = 0; i < 10; i++)
        var_argv[i] = va_arg(args, long);
    va_end(args);

    // Logging
    FILE *lf = fopen("/tmp/syscall_log.txt", "w");
    if (lf)
    {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);

        fprintf(lf, "[%02d:%02d:%02d] syscall(%ld)",
                tm.tm_hour, tm.tm_min, tm.tm_sec, number);

        for (int i = 0; i < 10; i++)
            fprintf(lf, ", arg[%d]=0x%lx", i, var_argv[i]);

        fprintf(lf, "\n");
        fclose(lf);
    }

    typedef bool (*policy_fn_t)(long number, long var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "syscall_policy");
    if (policy && !policy(number, var_argv))
        abort();

    return syscall(number, var_argv[0], var_argv[1], var_argv[2], var_argv[3], var_argv[4], var_argv[5]);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long sysconf_wrapper(int name)
{
    typedef bool (*policy_fn_t)(int name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sysconf_policy");
    if (policy && !policy(name))
        abort();
    return sysconf(name);
}

// #include <unistd.h>
// #include <linux/sysctl.h>
// #include <unistd.h>
// #include <sys/syscall.h>
// #include <string.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <linux/sysctl.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int sysctl_wrapper(struct __sysctl_args *args)
// {
//     typedef bool (*policy_fn_t)(struct __sysctl_args *args);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sysctl_policy");
//     if (policy && !policy(args))
//         abort();
//     return sysctl(args);
// }

#include <sys/sysinfo.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int sysinfo_wrapper(struct sysinfo *info)
{
    typedef bool (*policy_fn_t)(struct sysinfo *info);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sysinfo_policy");
    if (policy && !policy(info))
        abort();
    return sysinfo(info);
}

#include <sys/klog.h>
#include <syslog.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>

void syslog_wrapper(int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    // Policy typedef: include variadic args via va_list
    typedef bool (*policy_fn_t)(int priority, const char *format, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "syslog_policy");
    if (policy && !policy(priority, format, args))
    {
        va_end(args);
        abort();
    }

    vsyslog(priority, format, args);
    va_end(args);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int system_wrapper(const char *command)
{
    typedef bool (*policy_fn_t)(const char *command);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "system_policy");
    if (policy && !policy(command))
        abort();
    return system(command);
}

#include <signal.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

sighandler_t sysv_signal_wrapper(int signum, sighandler_t handler)
{
    typedef bool (*policy_fn_t)(int signum, sighandler_t handler);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "sysv_signal_policy");
    if (policy && !policy(signum, handler))
        abort();
    return sysv_signal(signum, handler);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcdrain_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcdrain_policy");
    if (policy && !policy(fd))
        abort();
    return tcdrain(fd);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcflow_wrapper(int fd, int action)
{
    typedef bool (*policy_fn_t)(int fd, int action);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcflow_policy");
    if (policy && !policy(fd, action))
        abort();
    return tcflow(fd, action);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcflush_wrapper(int fd, int queue_selector)
{
    typedef bool (*policy_fn_t)(int fd, int queue_selector);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcflush_policy");
    if (policy && !policy(fd, queue_selector))
        abort();
    return tcflush(fd, queue_selector);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcgetattr_wrapper(int fd, struct termios *termios_p)
{
    //wakka printffrom tcgetattr\n");
    typedef bool (*policy_fn_t)(int fd, struct termios *termios_p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcgetattr_policy");
    if (policy && !policy(fd, termios_p))
        abort();
    return tcgetattr(fd, termios_p);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t tcgetpgrp_wrapper(int fd)
{
    //wakka printffrom tcgetpgrp\n");
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcgetpgrp_policy");
    if (policy && !policy(fd))
        abort();
    return tcgetpgrp(fd);
}

#include <termios.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t tcgetsid_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcgetsid_policy");
    if (policy && !policy(fd))
        abort();
    return tcgetsid(fd);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcsendbreak_wrapper(int fd, int duration)
{
    typedef bool (*policy_fn_t)(int fd, int duration);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcsendbreak_policy");
    if (policy && !policy(fd, duration))
        abort();
    return tcsendbreak(fd, duration);
}

#include <termios.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcsetattr_wrapper(int fd, int optional_actions, const struct termios *termios_p)
{
    //wakka printffrom tcsetattr\n");
    typedef bool (*policy_fn_t)(int fd, int optional_actions, const struct termios *termios_p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcsetattr_policy");
    if (policy && !policy(fd, optional_actions, termios_p))
        abort();
    return tcsetattr(fd, optional_actions, termios_p);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tcsetpgrp_wrapper(int fd, pid_t pgrp)
{
    typedef bool (*policy_fn_t)(int fd, pid_t pgrp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tcsetpgrp_policy");
    if (policy && !policy(fd, pgrp))
        abort();
    return tcsetpgrp(fd, pgrp);
}

#include <search.h>
#include <search.h>
#include <search.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *tdelete_wrapper(const void *key, void **rootp, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(const void *key, void **rootp, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tdelete_policy");
    if (policy && !policy(key, rootp, compar))
        abort();
    return tdelete(key, rootp, compar);
}

#include <search.h>
#include <search.h>
#include <search.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void tdestroy_wrapper(void *root, void (*free_node)(void *node))
{
    typedef bool (*policy_fn_t)(void *root, void (*free_node)(void *node));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tdestroy_policy");
    if (policy && !policy(root, free_node))
        abort();
    tdestroy(root, free_node);
}

#include <fcntl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t tee_wrapper(int fd_in, int fd_out, size_t len, unsigned int flags)
{
    typedef bool (*policy_fn_t)(int fd_in, int fd_out, size_t len, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tee_policy");
    if (policy && !policy(fd_in, fd_out, len, flags))
        abort();
    return tee(fd_in, fd_out, len, flags);
}

#include <dirent.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

long telldir_wrapper(DIR *dirp)
{
    typedef bool (*policy_fn_t)(DIR *dirp);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "telldir_policy");
    if (policy && !policy(dirp))
        abort();
    return telldir(dirp);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *tempnam_wrapper(const char *dir, const char *pfx)
{
    typedef bool (*policy_fn_t)(const char *dir, const char *pfx);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tempnam_policy");
    if (policy && !policy(dir, pfx))
        abort();
    return tempnam(dir, pfx);
}

#include <libintl.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *textdomain_wrapper(const char *domainname)
{
    typedef bool (*policy_fn_t)(const char *domainname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "textdomain_policy");
    if (policy && !policy(domainname))
        abort();
    return textdomain(domainname);
}

#include <search.h>
#include <search.h>
#include <search.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *tfind_wrapper(const void *key, void *const *rootp, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(const void *key, void *const *rootp, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tfind_policy");
    if (policy && !policy(key, rootp, compar))
        abort();
    return tfind(key, rootp, compar);
}

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tgkill_wrapper(int tgid, int tid, int sig)
{
    typedef bool (*policy_fn_t)(int tgid, int tid, int sig);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tgkill_policy");
    if (policy && !policy(tgid, tid, sig))
        abort();
    return tgkill(tgid, tid, sig);
}

// Could not parse: time_t time(time_t *tloc)

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

time_t timegm_wrapper(struct tm *tm)
{
    typedef bool (*policy_fn_t)(struct tm *tm);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timegm_policy");
    if (policy && !policy(tm))
        abort();
    return timegm(tm);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

time_t timelocal_wrapper(struct tm *tm)
{
    typedef bool (*policy_fn_t)(struct tm *tm);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timelocal_policy");
    if (policy && !policy(tm))
        abort();
    return timelocal(tm);
}

#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timer_create_wrapper(clockid_t clockid, struct sigevent *sevp, timer_t *timerid)
{
    typedef bool (*policy_fn_t)(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timer_create_policy");
    if (policy && !policy(clockid, sevp, timerid))
        abort();
    return timer_create(clockid, sevp, timerid);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timer_delete_wrapper(timer_t timerid)
{
    typedef bool (*policy_fn_t)(timer_t timerid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timer_delete_policy");
    if (policy && !policy(timerid))
        abort();
    return timer_delete(timerid);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timer_getoverrun_wrapper(timer_t timerid)
{
    typedef bool (*policy_fn_t)(timer_t timerid);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timer_getoverrun_policy");
    if (policy && !policy(timerid))
        abort();
    return timer_getoverrun(timerid);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timer_gettime_wrapper(timer_t timerid, struct itimerspec *curr_value)
{
    typedef bool (*policy_fn_t)(timer_t timerid, struct itimerspec *curr_value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timer_gettime_policy");
    if (policy && !policy(timerid, curr_value))
        abort();
    return timer_gettime(timerid, curr_value);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timer_settime_wrapper(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value)
{
    typedef bool (*policy_fn_t)(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timer_settime_policy");
    if (policy && !policy(timerid, flags, new_value, old_value))
        abort();
    return timer_settime(timerid, flags, new_value, old_value);
}

#include <sys/timerfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timerfd_create_wrapper(int clockid, int flags)
{
    typedef bool (*policy_fn_t)(int clockid, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timerfd_create_policy");
    if (policy && !policy(clockid, flags))
        abort();
    return timerfd_create(clockid, flags);
}

#include <sys/timerfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timerfd_gettime_wrapper(int fd, struct itimerspec *curr_value)
{
    typedef bool (*policy_fn_t)(int fd, struct itimerspec *curr_value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timerfd_gettime_policy");
    if (policy && !policy(fd, curr_value))
        abort();
    return timerfd_gettime(fd, curr_value);
}

#include <sys/timerfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int timerfd_settime_wrapper(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value)
{
    typedef bool (*policy_fn_t)(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "timerfd_settime_policy");
    if (policy && !policy(fd, flags, new_value, old_value))
        abort();
    return timerfd_settime(fd, flags, new_value, old_value);
}

#include <sys/times.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

clock_t times_wrapper(struct tms *buf)
{
    typedef bool (*policy_fn_t)(struct tms *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "times_policy");
    if (policy && !policy(buf))
        abort();
    return times(buf);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

FILE *tmpfile_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tmpfile_policy");
    if (policy && !policy())
        abort();
    return tmpfile();
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *tmpnam_wrapper(char *s)
{
    typedef bool (*policy_fn_t)(char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tmpnam_policy");
    if (policy && !policy(s))
        abort();
    return tmpnam(s);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *tmpnam_r_wrapper(char *s)
{
    typedef bool (*policy_fn_t)(char *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tmpnam_r_policy");
    if (policy && !policy(s))
        abort();
    return tmpnam_r(s);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int toascii_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "toascii_policy");
    if (policy && !policy(c))
        abort();
    return toascii(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tolower_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tolower_policy");
    if (policy && !policy(c))
        abort();
    return tolower(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int tolower_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tolower_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return tolower_l(c, locale);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int toupper_wrapper(int c)
{
    typedef bool (*policy_fn_t)(int c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "toupper_policy");
    if (policy && !policy(c))
        abort();
    return toupper(c);
}

#include <ctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int toupper_l_wrapper(int c, locale_t locale)
{
    typedef bool (*policy_fn_t)(int c, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "toupper_l_policy");
    if (policy && !policy(c, locale))
        abort();
    return toupper_l(c, locale);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t towctrans_wrapper(wint_t wc, wctrans_t desc)
{
    typedef bool (*policy_fn_t)(wint_t wc, wctrans_t desc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "towctrans_policy");
    if (policy && !policy(wc, desc))
        abort();
    return towctrans(wc, desc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t towlower_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "towlower_policy");
    if (policy && !policy(wc))
        abort();
    return towlower(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t towlower_l_wrapper(wint_t wc, locale_t locale)
{
    typedef bool (*policy_fn_t)(wint_t wc, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "towlower_l_policy");
    if (policy && !policy(wc, locale))
        abort();
    return towlower_l(wc, locale);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t towupper_wrapper(wint_t wc)
{
    typedef bool (*policy_fn_t)(wint_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "towupper_policy");
    if (policy && !policy(wc))
        abort();
    return towupper(wc);
}

#include <wctype.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t towupper_l_wrapper(wint_t wc, locale_t locale)
{
    typedef bool (*policy_fn_t)(wint_t wc, locale_t locale);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "towupper_l_policy");
    if (policy && !policy(wc, locale))
        abort();
    return towupper_l(wc, locale);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int truncate_wrapper(const char *path, off_t length)
{
    typedef bool (*policy_fn_t)(const char *path, off_t length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "truncate_policy");
    if (policy && !policy(path, length))
        abort();
    return truncate(path, length);
}

#include <unistd.h>
#include <sys/types.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int truncate64_wrapper(const char *path, off_t length)
{
    typedef bool (*policy_fn_t)(const char *path, off_t length);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "truncate64_policy");
    if (policy && !policy(path, length))
        abort();
    return truncate64(path, length);
}

#include <search.h>
#include <search.h>
#include <search.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *tsearch_wrapper(const void *key, void **rootp, int (*compar)(const void *, const void *))
{
    typedef bool (*policy_fn_t)(const void *key, void **rootp, int (*compar)(const void *, const void *));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tsearch_policy");
    if (policy && !policy(key, rootp, compar))
        abort();
    return tsearch(key, rootp, compar);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

char *ttyname_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ttyname_policy");
    if (policy && !policy(fd))
        abort();
    return ttyname(fd);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ttyname_r_wrapper(int fd, char *buf, size_t buflen)
{
    typedef bool (*policy_fn_t)(int fd, char *buf, size_t buflen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ttyname_r_policy");
    if (policy && !policy(fd, buf, buflen))
        abort();
    return ttyname_r(fd, buf, buflen);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ttyslot_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ttyslot_policy");
    if (policy && !policy())
        abort();
    return ttyslot();
}

#include <search.h>
#include <search.h>
#include <search.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void twalk_wrapper(const void *root, void (*action)(const void *node, const VISIT which, const int depth))
{
    typedef bool (*policy_fn_t)(const void *root, void (*action)(const void *node, const VISIT which, const int depth));
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "twalk_policy");
    if (policy && !policy(root, action))
        abort();
    twalk(root, action);
}

#include <search.h>
#include <search.h>
#include <search.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void twalk_r_wrapper(const void *root, void (*action)(const void *nodep, VISIT which, void *closure), void *closure)
{
    typedef bool (*policy_fn_t)(const void *root, void (*action)(const void *nodep, VISIT which, void *closure), void *closure);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "twalk_r_policy");
    if (policy && !policy(root, action, closure))
        abort();
    twalk_r(root, action, closure);
}

#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void tzset_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "tzset_policy");
    if (policy && !policy())
        abort();
    tzset();
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

useconds_t ualarm_wrapper(useconds_t usecs, useconds_t interval)
{
    typedef bool (*policy_fn_t)(useconds_t usecs, useconds_t interval);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ualarm_policy");
    if (policy && !policy(usecs, interval))
        abort();
    return ualarm(usecs, interval);
}

#include <shadow.h>
#include <shadow.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ulckpwdf_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ulckpwdf_policy");
    if (policy && !policy())
        abort();
    return ulckpwdf();
}

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

mode_t umask_wrapper(mode_t mask)
{
    typedef bool (*policy_fn_t)(mode_t mask);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "umask_policy");
    if (policy && !policy(mask))
        abort();
    return umask(mask);
}

#include <sys/mount.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int umount_wrapper(const char *target)
{
    typedef bool (*policy_fn_t)(const char *target);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "umount_policy");
    if (policy && !policy(target))
        abort();
    return umount(target);
}

#include <sys/mount.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int umount2_wrapper(const char *target, int flags)
{
    typedef bool (*policy_fn_t)(const char *target, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "umount2_policy");
    if (policy && !policy(target, flags))
        abort();
    return umount2(target, flags);
}

#include <sys/utsname.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int uname_wrapper(struct utsname *buf)
{
    //wakka printffrom uname\n");
    typedef bool (*policy_fn_t)(struct utsname *buf);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "uname_policy");
    if (policy && !policy(buf))
        abort();
    return uname(buf);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int ungetc_wrapper(int c, FILE *stream)
{
    //wakka printffrom ungetc\n");
    typedef bool (*policy_fn_t)(int c, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ungetc_policy");
    if (policy && !policy(c, stream))
        abort();
    return ungetc(c, stream);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wint_t ungetwc_wrapper(wint_t wc, FILE *stream)
{
    typedef bool (*policy_fn_t)(wint_t wc, FILE *stream);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ungetwc_policy");
    if (policy && !policy(wc, stream))
        abort();
    return ungetwc(wc, stream);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int unlink_wrapper(const char *pathname)
{
    //wakka printffrom unlink\n");
    typedef bool (*policy_fn_t)(const char *pathname);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "unlink_policy");
    if (policy && !policy(pathname))
        abort();
    return unlink(pathname);
}

#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int unlinkat_wrapper(int dirfd, const char *pathname, int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "unlinkat_policy");
    if (policy && !policy(dirfd, pathname, flags))
        abort();
    return unlinkat(dirfd, pathname, flags);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int unlockpt_wrapper(int fd)
{
    typedef bool (*policy_fn_t)(int fd);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "unlockpt_policy");
    if (policy && !policy(fd))
        abort();
    return unlockpt(fd);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int unsetenv_wrapper(const char *name)
{
    typedef bool (*policy_fn_t)(const char *name);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "unsetenv_policy");
    if (policy && !policy(name))
        abort();
    return unsetenv(name);
}

#include <sched.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int unshare_wrapper(int flags)
{
    typedef bool (*policy_fn_t)(int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "unshare_policy");
    if (policy && !policy(flags))
        abort();
    return unshare(flags);
}

#include <utmp.h>
#include <utmpx.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void updwtmp_wrapper(const char *wtmp_file, const struct utmp *ut)
{
    typedef bool (*policy_fn_t)(const char *wtmp_file, const struct utmp *ut);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "updwtmp_policy");
    if (policy && !policy(wtmp_file, ut))
        abort();
    updwtmp(wtmp_file, ut);
}

#include <utmp.h>
#include <utmpx.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void updwtmpx_wrapper(const char *wtmpx_file, const struct utmpx *utx)
{
    typedef bool (*policy_fn_t)(const char *wtmpx_file, const struct utmpx *utx);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "updwtmpx_policy");
    if (policy && !policy(wtmpx_file, utx))
        abort();
    updwtmpx(wtmpx_file, utx);
}

// #include <unistd.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int uselib_wrapper(const char *library)
// {
//     typedef bool (*policy_fn_t)(const char *library);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "uselib_policy");
//     if (policy && !policy(library))
//         abort();
//     return uselib(library);
// }

#include <locale.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

locale_t uselocale_wrapper(locale_t newloc)
{
    typedef bool (*policy_fn_t)(locale_t newloc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "uselocale_policy");
    if (policy && !policy(newloc))
        abort();
    return uselocale(newloc);
}

#include <unistd.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int usleep_wrapper(useconds_t usec)
{
    typedef bool (*policy_fn_t)(useconds_t usec);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "usleep_policy");
    if (policy && !policy(usec))
        abort();
    return usleep(usec);
}

// #include <sys/types.h>
// #include <unistd.h>
// #include <ustat.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int ustat_wrapper(dev_t dev, struct ustat *ubuf) {
//     typedef bool (*policy_fn_t)(dev_t dev, struct ustat *ubuf);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "ustat_policy");
//     if(policy && !policy(dev, ubuf)) abort();
//     return ustat(dev, ubuf);
// }

#include <sys/types.h>
#include <utime.h>
#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int utime_wrapper(const char *filename, const struct utimbuf *times)
{
    typedef bool (*policy_fn_t)(const char *filename, const struct utimbuf *times);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "utime_policy");
    if (policy && !policy(filename, times))
        abort();
    return utime(filename, times);
}

#include <fcntl.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int utimensat_wrapper(int dirfd, const char *pathname, const struct timespec times[2], int flags)
{
    typedef bool (*policy_fn_t)(int dirfd, const char *pathname, const struct timespec times[2], int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "utimensat_policy");
    if (policy && !policy(dirfd, pathname, times, flags))
        abort();
    return utimensat(dirfd, pathname, times, flags);
}

#include <sys/types.h>
#include <utime.h>
#include <sys/time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int utimes_wrapper(const char *filename, const struct timeval times[2])
{
    typedef bool (*policy_fn_t)(const char *filename, const struct timeval times[2]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "utimes_policy");
    if (policy && !policy(filename, times))
        abort();
    return utimes(filename, times);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int utmpname_wrapper(const char *file)
{
    typedef bool (*policy_fn_t)(const char *file);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "utmpname_policy");
    if (policy && !policy(file))
        abort();
    return utmpname(file);
}

#include <utmp.h>
#include <utmpx.h>
#include <utmp.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <utmp.h>
#include <time.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int utmpxname_wrapper(const char *file)
{
    typedef bool (*policy_fn_t)(const char *file);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "utmpxname_policy");
    if (policy && !policy(file))
        abort();
    return utmpxname(file);
}

#include <stdlib.h>
#include <malloc.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void *valloc_wrapper(size_t size)
{
    typedef bool (*policy_fn_t)(size_t size);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "valloc_policy");
    if (policy && !policy(size))
        abort();
    return valloc(size);
}

#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vasprintf_wrapper(char **strp, const char *fmt, va_list ap)
{
    typedef bool (*policy_fn_t)(char **strp, const char *fmt, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vasprintf_policy");
    if (policy && !policy(strp, fmt, ap))
        abort();
    return vasprintf(strp, fmt, ap);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vdprintf_wrapper(int fd, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(int fd, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vdprintf_policy");
    if (policy && !policy(fd, format, ap))
        abort();
    return vdprintf(fd, format, ap);
}

#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void verr_wrapper(int eval, const char *fmt, va_list args)
{
    typedef bool (*policy_fn_t)(int eval, const char *fmt, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "verr_policy");
    if (policy && !policy(eval, fmt, args))
        abort();
    verr(eval, fmt, args);
}

#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void verrx_wrapper(int eval, const char *fmt, va_list args)
{
    typedef bool (*policy_fn_t)(int eval, const char *fmt, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "verrx_policy");
    if (policy && !policy(eval, fmt, args))
        abort();
    verrx(eval, fmt, args);
}

#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int versionsort_wrapper(const struct dirent **a, const struct dirent **b)
{
    typedef bool (*policy_fn_t)(const struct dirent **a, const struct dirent **b);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "versionsort_policy");
    if (policy && !policy(a, b))
        abort();
    return versionsort(a, b);
}

#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t vfork_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vfork_policy");
    if (policy && !policy())
        abort();
    return vfork();
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vfprintf_wrapper(FILE *stream, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(FILE *stream, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vfprintf_policy");
    if (policy && !policy(stream, format, ap))
        abort();
    return vfprintf(stream, format, ap);
}

#include <stdio.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vfscanf_wrapper(FILE *stream, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(FILE *stream, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vfscanf_policy");
    if (policy && !policy(stream, format, ap))
        abort();
    return vfscanf(stream, format, ap);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vfwprintf_wrapper(FILE *stream, const wchar_t *format, va_list args)
{
    typedef bool (*policy_fn_t)(FILE *stream, const wchar_t *format, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vfwprintf_policy");
    if (policy && !policy(stream, format, args))
        abort();
    return vfwprintf(stream, format, args);
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vhangup_wrapper(void)
{
    typedef bool (*policy_fn_t)(void);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vhangup_policy");
    if (policy && !policy())
        abort();
    return vhangup();
}

// #include <sys/time.h>
// #include <sys/resource.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <time.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <sys/resource.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int vlimit_wrapper(int resource, int value)
// {
//     typedef bool (*policy_fn_t)(int resource, int value);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vlimit_policy");
//     if (policy && !policy(resource, value))
//         abort();
//     return vlimit(resource, value);
// }

#include <fcntl.h>
#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t vmsplice_wrapper(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)
{
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vmsplice_policy");
    if (policy && !policy(fd, iov, nr_segs, flags))
        abort();
    return vmsplice(fd, iov, nr_segs, flags);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vprintf_wrapper(const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vprintf_policy");
    if (policy && !policy(format, ap))
        abort();
    return vprintf(format, ap);
}

#include <stdio.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vscanf_wrapper(const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vscanf_policy");
    if (policy && !policy(format, ap))
        abort();
    return vscanf(format, ap);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vsnprintf_wrapper(char *str, size_t size, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(char *str, size_t size, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vsnprintf_policy");
    if (policy && !policy(str, size, format, ap))
        abort();
    return vsnprintf(str, size, format, ap);
}

int __vsnprintf_chk_wrapper(char *str, size_t size, int flags, size_t slen, const char *format, va_list ap)
{
    //wakka printfhello from vsnprintf_chk\n");
    typedef bool (*policy_fn_t)(char *str, size_t size, int flags, size_t slen, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "__vsnprintf_chk_policy");
    if (policy && !policy(str, size, flags, slen, format, ap))
        abort();
    return __vsnprintf_chk(str, size, flags, slen, format, ap);
}

#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vsprintf_wrapper(char *str, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(char *str, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vsprintf_policy");
    if (policy && !policy(str, format, ap))
        abort();
    return vsprintf(str, format, ap);
}

#include <stdio.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vsscanf_wrapper(const char *str, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(const char *str, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vsscanf_policy");
    if (policy && !policy(str, format, ap))
        abort();
    return vsscanf(str, format, ap);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vswprintf_wrapper(wchar_t *wcs, size_t maxlen, const wchar_t *format, va_list args)
{
    typedef bool (*policy_fn_t)(wchar_t *wcs, size_t maxlen, const wchar_t *format, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vswprintf_policy");
    if (policy && !policy(wcs, maxlen, format, args))
        abort();
    return vswprintf(wcs, maxlen, format, args);
}

#include <syslog.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void vsyslog_wrapper(int priority, const char *format, va_list ap)
{
    typedef bool (*policy_fn_t)(int priority, const char *format, va_list ap);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vsyslog_policy");
    if (policy && !policy(priority, format, ap))
        abort();
    vsyslog(priority, format, ap);
}

// #include <sys/time.h>
// #include <sys/resource.h>

// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <stdarg.h>

// int vtimes_wrapper(struct vtimes *current, struct vtimes *child)
// {
//     typedef bool (*policy_fn_t)(struct vtimes *current, struct vtimes *child);
//     policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vtimes_policy");
//     if (policy && !policy(current, child))
//         abort();
//     return vtimes(current, child);
// }

#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void vwarn_wrapper(const char *fmt, va_list args)
{
    typedef bool (*policy_fn_t)(const char *fmt, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vwarn_policy");
    if (policy && !policy(fmt, args))
        abort();
    vwarn(fmt, args);
}

#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void vwarnx_wrapper(const char *fmt, va_list args)
{
    typedef bool (*policy_fn_t)(const char *fmt, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vwarnx_policy");
    if (policy && !policy(fmt, args))
        abort();
    vwarnx(fmt, args);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int vwprintf_wrapper(const wchar_t *format, va_list args)
{
    typedef bool (*policy_fn_t)(const wchar_t *format, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "vwprintf_policy");
    if (policy && !policy(format, args))
        abort();
    return vwprintf(format, args);
}

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t wait_wrapper(int *wstatus)
{
    typedef bool (*policy_fn_t)(int *wstatus);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wait_policy");
    if (policy && !policy(wstatus))
        abort();
    return wait(wstatus);
}

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t wait3_wrapper(int *wstatus, int options, struct rusage *rusage)
{
    typedef bool (*policy_fn_t)(int *wstatus, int options, struct rusage *rusage);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wait3_policy");
    if (policy && !policy(wstatus, options, rusage))
        abort();
    return wait3(wstatus, options, rusage);
}

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t wait4_wrapper(pid_t pid, int *wstatus, int options, struct rusage *rusage)
{
    typedef bool (*policy_fn_t)(pid_t pid, int *wstatus, int options, struct rusage *rusage);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wait4_policy");
    if (policy && !policy(pid, wstatus, options, rusage))
        abort();
    return wait4(pid, wstatus, options, rusage);
}

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int waitid_wrapper(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
    typedef bool (*policy_fn_t)(idtype_t idtype, id_t id, siginfo_t *infop, int options);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "waitid_policy");
    if (policy && !policy(idtype, id, infop, options))
        abort();
    return waitid(idtype, id, infop, options);
}

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

pid_t waitpid_wrapper(pid_t pid, int *wstatus, int options)
{
    typedef bool (*policy_fn_t)(pid_t pid, int *wstatus, int options);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "waitpid_policy");
    if (policy && !policy(pid, wstatus, options))
        abort();
    return waitpid(pid, wstatus, options);
}

#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>

void warn_wrapper(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    typedef bool (*policy_fn_t)(const char *fmt, va_list args);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "warn_policy");
    if (policy && !policy(fmt, args))
    {
        va_end(args);
        abort();
    }

    vwarn(fmt, args); // no return value
    va_end(args);
}

#include <err.h>
#include <stdarg.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void warnx_wrapper(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(const char *fmt, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "warnx_policy");
    if (policy && !policy(fmt, var_argv))
    {
        va_end(args);
        abort();
    }

    vwarnx(fmt, args); // no return value, it's void
    va_end(args);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcpcpy_wrapper(wchar_t *dest, const wchar_t *src)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcpcpy_policy");
    if (policy && !policy(dest, src))
        abort();
    return wcpcpy(dest, src);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcpncpy_wrapper(wchar_t *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcpncpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wcpncpy(dest, src, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcrtomb_wrapper(char *s, wchar_t wc, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(char *s, wchar_t wc, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcrtomb_policy");
    if (policy && !policy(s, wc, ps))
        abort();
    return wcrtomb(s, wc, ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wcscasecmp_wrapper(const wchar_t *s1, const wchar_t *s2)
{
    typedef bool (*policy_fn_t)(const wchar_t *s1, const wchar_t *s2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcscasecmp_policy");
    if (policy && !policy(s1, s2))
        abort();
    return wcscasecmp(s1, s2);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcscat_wrapper(wchar_t *dest, const wchar_t *src)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcscat_policy");
    if (policy && !policy(dest, src))
        abort();
    return wcscat(dest, src);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcschr_wrapper(const wchar_t *wcs, wchar_t wc)
{
    typedef bool (*policy_fn_t)(const wchar_t *, wchar_t);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "wcschr_policy");

    if (policy && !policy(wcs, wc))
        abort();

    return const_cast<wchar_t *>(wcschr(wcs, wc));
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wcscmp_wrapper(const wchar_t *s1, const wchar_t *s2)
{
    typedef bool (*policy_fn_t)(const wchar_t *s1, const wchar_t *s2);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcscmp_policy");
    if (policy && !policy(s1, s2))
        abort();
    return wcscmp(s1, s2);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcscpy_wrapper(wchar_t *dest, const wchar_t *src)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcscpy_policy");
    if (policy && !policy(dest, src))
        abort();
    return wcscpy(dest, src);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcscspn_wrapper(const wchar_t *wcs, const wchar_t *reject)
{
    typedef bool (*policy_fn_t)(const wchar_t *wcs, const wchar_t *reject);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcscspn_policy");
    if (policy && !policy(wcs, reject))
        abort();
    return wcscspn(wcs, reject);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcsdup_wrapper(const wchar_t *s)
{
    typedef bool (*policy_fn_t)(const wchar_t *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsdup_policy");
    if (policy && !policy(s))
        abort();
    return wcsdup(s);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcslen_wrapper(const wchar_t *s)
{
    typedef bool (*policy_fn_t)(const wchar_t *s);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcslen_policy");
    if (policy && !policy(s))
        abort();
    return wcslen(s);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wcsncasecmp_wrapper(const wchar_t *s1, const wchar_t *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const wchar_t *s1, const wchar_t *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsncasecmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return wcsncasecmp(s1, s2, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcsncat_wrapper(wchar_t *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsncat_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wcsncat(dest, src, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wcsncmp_wrapper(const wchar_t *s1, const wchar_t *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const wchar_t *s1, const wchar_t *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsncmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return wcsncmp(s1, s2, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcsncpy_wrapper(wchar_t *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsncpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wcsncpy(dest, src, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcsnlen_wrapper(const wchar_t *s, size_t maxlen)
{
    typedef bool (*policy_fn_t)(const wchar_t *s, size_t maxlen);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsnlen_policy");
    if (policy && !policy(s, maxlen))
        abort();
    return wcsnlen(s, maxlen);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcsnrtombs_wrapper(char *dest, const wchar_t **src, size_t nwc, size_t len, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(char *dest, const wchar_t **src, size_t nwc, size_t len, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsnrtombs_policy");
    if (policy && !policy(dest, src, nwc, len, ps))
        abort();
    return wcsnrtombs(dest, src, nwc, len, ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcspbrk_wrapper(const wchar_t *wcs, const wchar_t *accept)
{
    typedef bool (*policy_fn_t)(const wchar_t *, const wchar_t *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "wcspbrk_policy");

    if (policy && !policy(wcs, accept))
        abort();

    return const_cast<wchar_t *>(wcspbrk(wcs, accept));
}


#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcsrchr_wrapper(const wchar_t *wcs, wchar_t wc)
{
    typedef bool (*policy_fn_t)(const wchar_t *, wchar_t);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "wcsrchr_policy");

    if (policy && !policy(wcs, wc))
        abort();

    return const_cast<wchar_t *>(wcsrchr(wcs, wc));
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcsrtombs_wrapper(char *dest, const wchar_t **src, size_t len, mbstate_t *ps)
{
    typedef bool (*policy_fn_t)(char *dest, const wchar_t **src, size_t len, mbstate_t *ps);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsrtombs_policy");
    if (policy && !policy(dest, src, len, ps))
        abort();
    return wcsrtombs(dest, src, len, ps);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcsspn_wrapper(const wchar_t *wcs, const wchar_t *accept)
{
    typedef bool (*policy_fn_t)(const wchar_t *wcs, const wchar_t *accept);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcsspn_policy");
    if (policy && !policy(wcs, accept))
        abort();
    return wcsspn(wcs, accept);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcsstr_wrapper(const wchar_t *haystack, const wchar_t *needle)
{
    typedef bool (*policy_fn_t)(const wchar_t *, const wchar_t *);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "wcsstr_policy");

    if (policy && !policy(haystack, needle))
        abort();

    return const_cast<wchar_t *>(wcsstr(haystack, needle));
}


#include <stddef.h>
#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

intmax_t wcstoimax_wrapper(const wchar_t *nptr, wchar_t **endptr, int base)
{
    typedef bool (*policy_fn_t)(const wchar_t *nptr, wchar_t **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcstoimax_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return wcstoimax(nptr, endptr, base);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wcstok_wrapper(wchar_t *wcs, const wchar_t *delim, wchar_t **ptr)
{
    typedef bool (*policy_fn_t)(wchar_t *wcs, const wchar_t *delim, wchar_t **ptr);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcstok_policy");
    if (policy && !policy(wcs, delim, ptr))
        abort();
    return wcstok(wcs, delim, ptr);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

size_t wcstombs_wrapper(char *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(char *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcstombs_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wcstombs(dest, src, n);
}

#include <stddef.h>
#include <inttypes.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

uintmax_t wcstoumax_wrapper(const wchar_t *nptr, wchar_t **endptr, int base)
{
    typedef bool (*policy_fn_t)(const wchar_t *nptr, wchar_t **endptr, int base);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcstoumax_policy");
    if (policy && !policy(nptr, endptr, base))
        abort();
    return wcstoumax(nptr, endptr, base);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wcswidth_wrapper(const wchar_t *s, size_t n)
{
    typedef bool (*policy_fn_t)(const wchar_t *s, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcswidth_policy");
    if (policy && !policy(s, n))
        abort();
    return wcswidth(s, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wctob_wrapper(wint_t c)
{
    typedef bool (*policy_fn_t)(wint_t c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wctob_policy");
    if (policy && !policy(c))
        abort();
    return wctob(c);
}

#include <stdlib.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wctomb_wrapper(char *s, wchar_t wc)
{
    typedef bool (*policy_fn_t)(char *s, wchar_t wc);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wctomb_policy");
    if (policy && !policy(s, wc))
        abort();
    return wctomb(s, wc);
}

// Could not parse: wctrans_t wctrans(const char *name)

// Could not parse: wctype_t wctype(const char *name)

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wcwidth_wrapper(wchar_t c)
{
    typedef bool (*policy_fn_t)(wchar_t c);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wcwidth_policy");
    if (policy && !policy(c))
        abort();
    return wcwidth(c);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>
wchar_t *wmemchr_wrapper(const wchar_t *s, wchar_t c, size_t n)
{
    typedef bool (*policy_fn_t)(const wchar_t *, wchar_t, size_t);
    policy_fn_t policy =
        (policy_fn_t)dlsym(RTLD_NEXT, "wmemchr_policy");

    if (policy && !policy(s, c, n))
        abort();

    return const_cast<wchar_t *>(wmemchr(s, c, n));
}


#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wmemcmp_wrapper(const wchar_t *s1, const wchar_t *s2, size_t n)
{
    typedef bool (*policy_fn_t)(const wchar_t *s1, const wchar_t *s2, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wmemcmp_policy");
    if (policy && !policy(s1, s2, n))
        abort();
    return wmemcmp(s1, s2, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wmemcpy_wrapper(wchar_t *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wmemcpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wmemcpy(dest, src, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wmemmove_wrapper(wchar_t *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wmemmove_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wmemmove(dest, src, n);
}

#include <string.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wmempcpy_wrapper(wchar_t *dest, const wchar_t *src, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *dest, const wchar_t *src, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wmempcpy_policy");
    if (policy && !policy(dest, src, n))
        abort();
    return wmempcpy(dest, src, n);
}

#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

wchar_t *wmemset_wrapper(wchar_t *wcs, wchar_t wc, size_t n)
{
    typedef bool (*policy_fn_t)(wchar_t *wcs, wchar_t wc, size_t n);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wmemset_policy");
    if (policy && !policy(wcs, wc, n))
        abort();
    return wmemset(wcs, wc, n);
}

#include <wordexp.h>
#include <stdio.h>
#include <stdlib.h>
#include <wordexp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wordexp_wrapper(const char *s, wordexp_t *p, int flags)
{
    typedef bool (*policy_fn_t)(const char *s, wordexp_t *p, int flags);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wordexp_policy");
    if (policy && !policy(s, p, flags))
        abort();
    return wordexp(s, p, flags);
}

#include <wordexp.h>
#include <stdio.h>
#include <stdlib.h>
#include <wordexp.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

void wordfree_wrapper(wordexp_t *p)
{
    typedef bool (*policy_fn_t)(wordexp_t *p);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wordfree_policy");
    if (policy && !policy(p))
        abort();
    wordfree(p);
}

#include <stdio.h>
#include <wchar.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

int wprintf_wrapper(const wchar_t *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *var_argv[64];
    int vi = 0;
    const char *next;
    while (vi < 63 && (next = va_arg(args, const char *)) != NULL)
        var_argv[vi++] = next;
    var_argv[vi] = NULL;

    typedef bool (*policy_fn_t)(const wchar_t *format, const char *var_argv[]);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "wprintf_policy");
    if (policy && !policy(format, var_argv))
    {
        va_end(args);
        abort();
    }

    int ret = vwprintf(format, args);
    va_end(args);
    return ret;
}

#include <unistd.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t write_wrapper(int fd, const void *buf, size_t count)

{
    //wakka printfFrom Write Wrapper\n");
    typedef bool (*policy_fn_t)(int fd, const void *buf, size_t count);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "write_policy");
    if (policy && !policy(fd, buf, count))
        abort();
    return write(fd, buf, count);
}

#include <sys/uio.h>

#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdarg.h>

ssize_t writev_wrapper(int fd, const struct iovec *iov, int iovcnt)
{
    //wakka printfhello from writev\n");
    typedef bool (*policy_fn_t)(int fd, const struct iovec *iov, int iovcnt);
    policy_fn_t policy = (policy_fn_t)dlsym(RTLD_NEXT, "writev_policy");
    if (policy && !policy(fd, iov, iovcnt))
        abort();
    return writev(fd, iov, iovcnt);
}





//////////// REAL WRAPPERS FOR rclcpp ////////////





    extern "C"
    void * _ZN6rclcpp12experimental19IntraProcessManagerC1Ev_wrapper()
    {
        //wakka printf[WRAP] rclcpp::experimental::IntraProcessManager::IntraProcessManager()\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp12experimental19IntraProcessManagerC1Ev");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real();
        mpk_exit_gate();
        return ret;
    }   

    extern "C"
    void * _ZN6rclcpp12experimental28SubscriptionIntraProcessBaseD2Ev_wrapper()
    {
        //wakka printf[WRAP] rclcpp::experimental::SubscriptionIntraProcessBase::~SubscriptionIntraProcessBase()\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp12experimental28SubscriptionIntraProcessBaseD2Ev");
            if (!real) abort();
        }
        mpk_entry_gate();  
        void * ret = real();
        mpk_exit_gate();    
        return ret;
    }

    extern "C"
    void * _ZN6rclcpp12get_c_stringERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE_wrapper(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const& a0)
    {
        //wakka printf[WRAP] rclcpp::get_c_string(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)\n");
        using Fn = void * (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp12get_c_stringERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE");
            if (!real) abort();
        }
        return real(a0);
    }

    extern "C"
    void * _ZN6rclcpp13PublisherBase19setup_intra_processEmSt10shared_ptrINS_12experimental19IntraProcessManagerEE_wrapper(unsigned long a0, std::shared_ptr<rclcpp::experimental::IntraProcessManager> a1)
    {
        //wakka printf[WRAP] rclcpp::PublisherBase::setup_intra_process(unsigned long, std::shared_ptr<rclcpp::experimental::IntraProcessManager>)\n");
        using Fn = void * (*)(unsigned long, std::shared_ptr<rclcpp::experimental::IntraProcessManager>);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp13PublisherBase19setup_intra_processEmSt10shared_ptrINS_12experimental19IntraProcessManagerEE");
            if (!real) abort();
        }
        return real(a0, a1);
    }

    extern "C"
    void * _ZN6rclcpp13PublisherBaseC2EPNS_15node_interfaces17NodeBaseInterfaceERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERK29rosidl_message_type_support_tRK23rcl_publisher_options_s_wrapper(rclcpp::node_interfaces::NodeBaseInterface* a0, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const& a1, rosidl_message_type_support_t const& a2, rcl_publisher_options_s const& a3)
    {
        //wakka printf[WRAP] rclcpp::PublisherBase::PublisherBase(rclcpp::node_interfaces::NodeBaseInterface*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, rosidl_message_type_support_t const&, rcl_publisher_options_s const&)\n");
        using Fn = void * (*)(rclcpp::node_interfaces::NodeBaseInterface*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, rosidl_message_type_support_t const&, rcl_publisher_options_s const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp13PublisherBaseC2EPNS_15node_interfaces17NodeBaseInterfaceERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERK29rosidl_message_type_support_tRK23rcl_publisher_options_s");
            if (!real) abort();
        }
        return real(a0, a1, a2, a3);
    }
extern "C"
void
_ZN6rclcpp13PublisherBaseD2Ev_wrapper(
    rclcpp::PublisherBase * self)
{
    //wakka printf[WRAP] rclcpp::PublisherBase::~PublisherBase() D2\n");

    using Fn = void (*)(rclcpp::PublisherBase*);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp13PublisherBaseD2Ev");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self);
    mpk_exit_gate();    
}


    extern "C"
    void * _ZN6rclcpp14GuardCondition7triggerEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::GuardCondition::trigger()\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp14GuardCondition7triggerEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real();
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZN6rclcpp14GuardConditionC1ESt10shared_ptrINS_7ContextEE29rcl_guard_condition_options_s_wrapper(std::shared_ptr<rclcpp::Context> a0, rcl_guard_condition_options_s a1)
    {
        //wakka printf[WRAP] rclcpp::GuardCondition::GuardCondition(std::shared_ptr<rclcpp::Context>, rcl_guard_condition_options_s)\n");
        using Fn = void * (*)(std::shared_ptr<rclcpp::Context>, rcl_guard_condition_options_s);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp14GuardConditionC1ESt10shared_ptrINS_7ContextEE29rcl_guard_condition_options_s");
            if (!real) abort();
        }
        return real(a0, a1);
    }

    extern "C"
    void * _ZN6rclcpp14GuardConditionD1Ev_wrapper()
    {
        //wakka printf[WRAP] rclcpp::GuardCondition::~GuardCondition()\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp14GuardConditionD1Ev");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret; 
    }

//  extern "C"
// void
// _ZN6rclcpp14ParameterValueC1EPKc_wrapper(
//     rclcpp::ParameterValue * self,
//     const char * a0)
// {
//     //wakka printf[WRAP] rclcpp::ParameterValue::ParameterValue(const char*)\n");

//     using Fn = void (*)(rclcpp::ParameterValue*, const char*);
//     static Fn real = nullptr;

//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//             "_ZN6rclcpp14ParameterValueC1EPKc");
//         if (!real) abort();
//     }

//     real(self, a0);
// }



    extern "C"
    void * _ZN6rclcpp14ParameterValueC1Eb_wrapper(bool a0)
    {
        //wakka printf[WRAP] rclcpp::ParameterValue::ParameterValue(bool)\n");
        using Fn = void * (*)(bool);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp14ParameterValueC1Eb");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0);
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZN6rclcpp14ParameterValueC1El_wrapper(long a0)
    {
        //wakka printf[WRAP] rclcpp::ParameterValue::ParameterValue(long)\n");
        using Fn = void * (*)(long);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp14ParameterValueC1El");
            if (!real) abort();
        }
        return real(a0);
    }

    extern "C"
    void * _ZN6rclcpp16SubscriptionBase19setup_intra_processEmSt8weak_ptrINS_12experimental19IntraProcessManagerEE_wrapper(unsigned long a0, std::weak_ptr<rclcpp::experimental::IntraProcessManager> a1)
    {
        //wakka printf[WRAP] rclcpp::SubscriptionBase::setup_intra_process(unsigned long, std::weak_ptr<rclcpp::experimental::IntraProcessManager>)\n");
        using Fn = void * (*)(unsigned long, std::weak_ptr<rclcpp::experimental::IntraProcessManager>);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp16SubscriptionBase19setup_intra_processEmSt8weak_ptrINS_12experimental19IntraProcessManagerEE");
            if (!real) abort();
        }
        return real(a0, a1);
    }

   #include <memory>
#include <rclcpp/subscription_base.hpp>

extern "C"
std::shared_ptr<rclcpp::SubscriptionBase>
_ZN6rclcpp16SubscriptionBase23get_subscription_handleEv_wrapper(void *self)
{
    //wakka printf[WRAP] rclcpp::SubscriptionBase::get_subscription_handle()\n");

    using Fn = std::shared_ptr<rclcpp::SubscriptionBase> (*)(void*);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp16SubscriptionBase23get_subscription_handleEv");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret = real(self);
    mpk_exit_gate();
    return ret;
}


    extern "C"
    void * _ZN6rclcpp16SubscriptionBaseC2EPNS_15node_interfaces17NodeBaseInterfaceERK29rosidl_message_type_support_tRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERK26rcl_subscription_options_sb_wrapper(rclcpp::node_interfaces::NodeBaseInterface* a0, rosidl_message_type_support_t const& a1, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const& a2, rcl_subscription_options_s const& a3, bool a4)
    {
        //wakka printf[WRAP] rclcpp::SubscriptionBase::SubscriptionBase(rclcpp::node_interfaces::NodeBaseInterface*, rosidl_message_type_support_t const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, rcl_subscription_options_s const&, bool)\n");
        using Fn = void * (*)(rclcpp::node_interfaces::NodeBaseInterface*, rosidl_message_type_support_t const&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, rcl_subscription_options_s const&, bool);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp16SubscriptionBaseC2EPNS_15node_interfaces17NodeBaseInterfaceERK29rosidl_message_type_support_tRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERK26rcl_subscription_options_sb");
            if (!real) abort();
        }
        return real(a0, a1, a2, a3, a4);
    }

extern "C"
void
_ZN6rclcpp16SubscriptionBaseD2Ev_wrapper(rclcpp::SubscriptionBase * self)
{
    //wakka printf[WRAP] rclcpp::SubscriptionBase::~SubscriptionBase()\n");

    using Fn = void (*)(rclcpp::SubscriptionBase *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZN6rclcpp16SubscriptionBaseD2Ev");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self);
    mpk_exit_gate();
}


    extern "C"
    void * _ZN6rclcpp17SerializedMessageC1ERKS0__wrapper(rclcpp::SerializedMessage const& a0)
    {
        //wakka printf[WRAP] rclcpp::SerializedMessage::SerializedMessage(rclcpp::SerializedMessage const&)\n");
        using Fn = void * (*)(rclcpp::SerializedMessage const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp17SerializedMessageC1ERKS0_");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real(a0);
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZN6rclcpp17SerializedMessageC1EmRK19rcutils_allocator_s_wrapper(unsigned long a0, rcutils_allocator_s const& a1)
    {
        //wakka printf[WRAP] rclcpp::SerializedMessage::SerializedMessage(unsigned long, rcutils_allocator_s const&)\n");
        using Fn = void * (*)(unsigned long, rcutils_allocator_s const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp17SerializedMessageC1EmRK19rcutils_allocator_s");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0, a1);
        mpk_exit_gate();
        return ret;
    }




   #include <rclcpp/qos_event.hpp>
#include <dlfcn.h>
#include <cstdio>

extern "C"
void
_ZN6rclcpp19QOSEventHandlerBase25set_on_new_event_callbackEPFvPKvmES2__wrapper(
    rclcpp::QOSEventHandlerBase * self,
    void (*callback)(void const *, size_t),
    void const * user_data)
{
    //wakka printf[WRAP] rclcpp::QOSEventHandlerBase::set_on_new_event_callback(callback, user_data)\n");

    using Fn = void (*)(rclcpp::QOSEventHandlerBase *,
                        void (*)(void const *, size_t),
                        void const *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp19QOSEventHandlerBase25set_on_new_event_callbackEPFvPKvmES2_");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self, callback, user_data);
    mpk_exit_gate();

}


    extern "C"
void
_ZN6rclcpp19QOSEventHandlerBaseD2Ev_wrapper(
    rclcpp::QOSEventHandlerBase * self)
{
    //wakka printf[WRAP] rclcpp::QOSEventHandlerBase::~QOSEventHandlerBase()\n");

    using Fn = void (*)(rclcpp::QOSEventHandlerBase *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp19QOSEventHandlerBaseD2Ev");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self);
    mpk_exit_gate();    

}


    extern "C"
    void * _ZN6rclcpp19get_c_vector_stringERKSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS6_EE_wrapper(std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > const& a0)
    {
        //wakka printf[WRAP] rclcpp::get_c_vector_string(std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > const&)\n");
        using Fn = void * (*)(std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp19get_c_vector_stringERKSt6vectorINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESaIS6_EE");
            if (!real) abort();
        }
        return real(a0);
    }

    extern "C"
    void * _ZN6rclcpp23qos_policy_kind_to_cstrERKNS_13QosPolicyKindE_wrapper(rclcpp::QosPolicyKind const& a0)
    {
        //wakka printf[WRAP] rclcpp::qos_policy_kind_to_cstr(rclcpp::QosPolicyKind const&)\n");
        using Fn = void * (*)(rclcpp::QosPolicyKind const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp23qos_policy_kind_to_cstrERKNS_13QosPolicyKindE");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real(a0);
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZN6rclcpp29UnsupportedEventTypeExceptionC1EiPK21rcutils_error_state_sRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE_wrapper(int a0, rcutils_error_state_s const* a1, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const& a2)
    {
        //wakka printf[WRAP] rclcpp::UnsupportedEventTypeException::UnsupportedEventTypeException(int, rcutils_error_state_s const*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)\n");
        using Fn = void * (*)(int, rcutils_error_state_s const*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp29UnsupportedEventTypeExceptionC1EiPK21rcutils_error_state_sRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE");
            if (!real) abort();
        }
        return real(a0, a1, a2);
    }

extern "C"
void _ZN6rclcpp3QoS10durabilityE27rmw_qos_durability_policy_e_wrapper(
    rclcpp::QoS *ret,
    const rclcpp::QoS *self,
    rmw_qos_durability_policy_e a0)
{
    //wakka printf[WRAP] QoS::durability()\n");

    using Fn = void (*)(rclcpp::QoS*, const rclcpp::QoS*, rmw_qos_durability_policy_e);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp3QoS10durabilityE27rmw_qos_durability_policy_e");
        if (!real) {
            //wakka printf[SKIP] No symbol exported for QoS::durability\n");
            *ret = *self;   // safe fallback: just copy input
            return;
        }
    }

    return real(ret, self, a0);
}


    extern "C"
    void * _ZN6rclcpp3QoS10livelinessE27rmw_qos_liveliness_policy_e_wrapper(rmw_qos_liveliness_policy_e a0)
    {
        //wakka printf[WRAP] rclcpp::QoS::liveliness(rmw_qos_liveliness_policy_e)\n");
        using Fn = void * (*)(rmw_qos_liveliness_policy_e);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp3QoS10livelinessE27rmw_qos_liveliness_policy_e");
            if (!real) abort();
        }
        return real(a0);
    }

extern "C"
void _ZN6rclcpp3QoS11reliabilityE28rmw_qos_reliability_policy_e(
    void *ret,
    const void *self,
    rmw_qos_reliability_policy_e a0)
{
    //wakka printf[WRAP] rclcpp::QoS::reliability(rmw_qos_reliability_policy_e)\n");

    using Fn = void (*)(void*, const void*, rmw_qos_reliability_policy_e);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp3QoS11reliabilityE28rmw_qos_reliability_policy_e");
        if (!real) abort();
    }

    real(ret, self, a0);
}


    extern "C"
    void * _ZN6rclcpp3QoS19get_rmw_qos_profileEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QoS::get_rmw_qos_profile()\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp3QoS19get_rmw_qos_profileEv");
            if (!real) abort();
        }
        return real();
    }

    extern "C"
    void * _ZN6rclcpp3QoS25liveliness_lease_durationERKNS_8DurationE_wrapper(rclcpp::Duration const& a0)
    {
        //wakka printf[WRAP] rclcpp::QoS::liveliness_lease_duration(rclcpp::Duration const&)\n");
        using Fn = void * (*)(rclcpp::Duration const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp3QoS25liveliness_lease_durationERKNS_8DurationE");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0);
        mpk_exit_gate();
        return ret;
    }   

    extern "C"
    void * _ZN6rclcpp3QoS31avoid_ros_namespace_conventionsEb_wrapper(bool a0)
    {
        //wakka printf[WRAP] rclcpp::QoS::avoid_ros_namespace_conventions(bool)\n");
        using Fn = void * (*)(bool);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp3QoS31avoid_ros_namespace_conventionsEb");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0);
        mpk_exit_gate();
        return ret;
    }

extern "C"
void _ZN6rclcpp3QoS7historyE24rmw_qos_history_policy_e_wrapper(
    void *ret,
    const void *self,
    rmw_qos_history_policy_e a0)
{
    //wakka printf[WRAP] rclcpp::QoS::history(rmw_qos_history_policy_e)\n");

    using Fn = void (*)(void*, const void*, rmw_qos_history_policy_e);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp3QoS7historyE24rmw_qos_history_policy_e");
        if (!real) abort();
    }

    real(ret, self, a0);
}


    extern "C"
    void * _ZN6rclcpp3QoS8deadlineERKNS_8DurationE_wrapper(rclcpp::Duration const& a0)
    {
        //wakka printf[WRAP] rclcpp::QoS::deadline(rclcpp::Duration const&)\n");
        using Fn = void * (*)(rclcpp::Duration const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp3QoS8deadlineERKNS_8DurationE");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0);
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZN6rclcpp3QoS8lifespanERKNS_8DurationE_wrapper(rclcpp::Duration const& a0)
    {
        //wakka printf[WRAP] rclcpp::QoS::lifespan(rclcpp::Duration const&)\n");
        using Fn = void * (*)(rclcpp::Duration const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp3QoS8lifespanERKNS_8DurationE");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0);
        mpk_exit_gate();
        return ret;
    }

#include <memory>

extern "C"
std::shared_ptr<rclcpp::node_interfaces::NodeTopicsInterface>
_ZN6rclcpp4Node25get_node_topics_interfaceEv_wrapper(void *self)
{
    //wakka printf[WRAP] rclcpp::Node::get_node_topics_interface()\n");

    using Fn =
        std::shared_ptr<rclcpp::node_interfaces::NodeTopicsInterface>
        (*)(void*);

    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZN6rclcpp4Node25get_node_topics_interfaceEv");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real(self);
    mpk_exit_gate();
    return ret;
}


#include <memory>
#include <rclcpp/node_interfaces/node_parameters_interface.hpp>

extern "C"
std::shared_ptr<rclcpp::node_interfaces::NodeParametersInterface>
_ZN6rclcpp4Node29get_node_parameters_interfaceEv_wrapper(void *self)
{
    //wakka printf[WRAP] rclcpp::Node::get_node_parameters_interface()\n");

    using Fn =
        std::shared_ptr<rclcpp::node_interfaces::NodeParametersInterface>
        (*)(void *);

    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZN6rclcpp4Node29get_node_parameters_interfaceEv");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real(self);
    mpk_exit_gate();
    return ret; 
}

#include <rclcpp/node.hpp>
#include <rclcpp/node_options.hpp>
#include <rclcpp/rclcpp.hpp>
#include <dlfcn.h>
#include <cstdio>

extern "C"
void
_ZN6rclcpp4NodeD2Ev_wrapper(rclcpp::Node * self)
{
    //wakka printf[WRAP] rclcpp::Node::~Node()\n");

    using Fn = void (*)(rclcpp::Node *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp4NodeD2Ev");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self);
    mpk_exit_gate();    
}


    extern "C"
    void * _ZN6rclcpp4initEiPKPKcRKNS_11InitOptionsENS_20SignalHandlerOptionsE_wrapper(int a0, char const* const* a1, rclcpp::InitOptions const& a2, rclcpp::SignalHandlerOptions a3)
    {
        //wakka printf[WRAP] rclcpp::init(int, char const* const*, rclcpp::InitOptions const&, rclcpp::SignalHandlerOptions)\n");
        using Fn = void * (*)(int, char const* const*, rclcpp::InitOptions const&, rclcpp::SignalHandlerOptions);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp4initEiPKPKcRKNS_11InitOptionsENS_20SignalHandlerOptionsE");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real(a0, a1, a2, a3);
        mpk_exit_gate();
        return ret;
    }


    extern "C"
    void * _ZN6rclcpp8DurationC1Eij_wrapper(int a0, unsigned int a1)
    {
        //wakka printf[WRAP] rclcpp::Duration::Duration(int, unsigned int)\n");
        using Fn = void * (*)(int, unsigned int);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp8DurationC1Eij");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0, a1);
        mpk_exit_gate();
        return ret;
    }

    #include <rclcpp/rclcpp.hpp>
#include <rclcpp/executor.hpp>
#include <rclcpp/node.hpp>        // <-- REQUIRED FOR rclcpp::Node
#include <memory>
#include <dlfcn.h>
#include <stdio.h>


   extern "C"
void *
_ZN6rclcpp8Executor8add_nodeESt10shared_ptrINS_4NodeEEb_wrapper(
    std::shared_ptr<rclcpp::Node> a0,
    bool a1)
{
    //wakka printf[WRAP] rclcpp::Executor::add_node(std::shared_ptr<rclcpp::Node>, bool)\n");

    using Fn = void * (*)(std::shared_ptr<rclcpp::Node>, bool);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp8Executor8add_nodeESt10shared_ptrINS_4NodeEEb");
        if (!real) abort();
    }

    return real(a0, a1);
}


    extern "C"
    void * _ZN6rclcpp8shutdownESt10shared_ptrINS_7ContextEERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE_wrapper(std::shared_ptr<rclcpp::Context> a0, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const& a1)
    {
        //wakka printf[WRAP] rclcpp::shutdown(std::shared_ptr<rclcpp::Context>, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)\n");
        using Fn = void * (*)(std::shared_ptr<rclcpp::Context>, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpp8shutdownESt10shared_ptrINS_7ContextEERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE");
            if (!real) abort();
        }
        return real(a0, a1);
    }



extern "C"
void _ZN6rclcpp9executors22SingleThreadedExecutor4spinEv_wrapper(
    void *self)
{
    //wakka printf[WRAP] SingleThreadedExecutor::spin()\n");

    using Fn = void (*)(void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZN6rclcpp9executors22SingleThreadedExecutor4spinEv");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self);
    mpk_exit_gate();
}

    #include <rclcpp/rclcpp.hpp>
#include <rclcpp/executor_options.hpp>
#include <rclcpp/executors/single_threaded_executor.hpp>
#include <dlfcn.h>
#include <stdio.h>


extern "C"
void
_ZN6rclcpp9executors22SingleThreadedExecutorC2ERKNS_15ExecutorOptionsE(
    rclcpp::executors::SingleThreadedExecutor* self,
    rclcpp::ExecutorOptions const& a0)
{
    //wakka printf[WRAP] SingleThreadedExecutor C2(const ExecutorOptions&)\n");

    using Fn = void (*)(rclcpp::executors::SingleThreadedExecutor*, 
                        rclcpp::ExecutorOptions const&);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9executors22SingleThreadedExecutorC2ERKNS_15ExecutorOptionsE");
        if (!real) abort();
    }

    real(self, a0);
}


extern "C"
void
_ZN6rclcpp9executors22SingleThreadedExecutorD1Ev_wrapper(
    void *self)
{
    //wakka printf[WRAP] SingleThreadedExecutor::~SingleThreadedExecutor() D1\n");

    using Fn = void (*)(void*);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9executors22SingleThreadedExecutorD1Ev");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self);
    mpk_exit_gate();
}


extern "C"
std::string
_ZN6rclcpp9to_stringB5cxx11ENS_13ParameterTypeE_wrapper(
    uint8_t a0)
{
    //wakka printf[WRAP] rclcpp::to_string(param type)\n");

    using Ret = std::string;
    using Arg = uint8_t;
    using Fn  = Ret (*)(Arg);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9to_stringB5cxx11ENS_13ParameterTypeE");
        if (!real) abort();
    }
    mpk_entry_gate();
    return real(a0);
    mpk_exit_gate();    
}
    extern "C"
    void * _ZN6rclcpplsERSoRKNS_13QosPolicyKindE_wrapper(std::basic_ostream<char, std::char_traits<char> >& a0, rclcpp::QosPolicyKind const& a1)
    {
        //wakka printf[WRAP] rclcpp::operator<<(std::basic_ostream<char, std::char_traits<char> >&, rclcpp::QosPolicyKind const&)\n");
        using Fn = void * (*)(std::basic_ostream<char, std::char_traits<char> >&, rclcpp::QosPolicyKind const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZN6rclcpplsERSoRKNS_13QosPolicyKindE");
            if (!real) abort();
        }
        return real(a0, a1);
    }

    extern "C"
    void * _ZNK6rclcpp11MessageInfo20get_rmw_message_infoEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::MessageInfo::get_rmw_message_info() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp11MessageInfo20get_rmw_message_infoEv");
            if (!real) abort();
        }
        return real();
    }

    extern "C"
    void * _ZNK6rclcpp13PublisherBase14get_actual_qosEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::PublisherBase::get_actual_qos() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp13PublisherBase14get_actual_qosEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real();
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZNK6rclcpp13PublisherBase22get_subscription_countEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::PublisherBase::get_subscription_count() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp13PublisherBase22get_subscription_countEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret; 
    }

#include <rclcpp/executors/single_threaded_executor.hpp>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

extern "C"
void
_ZN6rclcpp9executors22SingleThreadedExecutorC1ERKNS_15ExecutorOptionsE_wrapper(
    rclcpp::executors::SingleThreadedExecutor * self,
    const rclcpp::ExecutorOptions & opt)
{
    //wakka printf[WRAP] SingleThreadedExecutor::SingleThreadedExecutor(const ExecutorOptions&)\n");

    using Fn = void (*)(rclcpp::executors::SingleThreadedExecutor *,
                        const rclcpp::ExecutorOptions &);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9executors22SingleThreadedExecutorC1ERKNS_15ExecutorOptionsE"
        );
        if (!real) abort();
    }
    mpk_entry_gate();
    real(self, opt);
    mpk_exit_gate();
}



    extern "C"
    void * _ZNK6rclcpp13PublisherBase33default_incompatible_qos_callbackER35rmw_qos_incompatible_event_status_s_wrapper(rmw_qos_incompatible_event_status_s& a0)
    {
        //wakka printf[WRAP] rclcpp::PublisherBase::default_incompatible_qos_callback(rmw_qos_incompatible_event_status_s&) const\n");
        using Fn = void * (*)(rmw_qos_incompatible_event_status_s&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp13PublisherBase33default_incompatible_qos_callbackER35rmw_qos_incompatible_event_status_s");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real(a0);
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZNK6rclcpp13PublisherBase36get_intra_process_subscription_countEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::PublisherBase::get_intra_process_subscription_count() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp13PublisherBase36get_intra_process_subscription_countEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZNK6rclcpp14ParameterValue8get_typeEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::ParameterValue::get_type() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp14ParameterValue8get_typeEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret; 
    }

    extern "C"
    void * _ZNK6rclcpp16SubscriptionBase14get_actual_qosEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::SubscriptionBase::get_actual_qos() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp16SubscriptionBase14get_actual_qosEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret; 
    }

    extern "C"
    void * _ZNK6rclcpp16SubscriptionBase14get_topic_nameEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::SubscriptionBase::get_topic_name() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp16SubscriptionBase14get_topic_nameEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret; 
    }

    extern "C"
    void * _ZNK6rclcpp16SubscriptionBase33default_incompatible_qos_callbackER35rmw_qos_incompatible_event_status_s_wrapper(rmw_qos_incompatible_event_status_s& a0)
    {
        //wakka printf[WRAP] rclcpp::SubscriptionBase::default_incompatible_qos_callback(rmw_qos_incompatible_event_status_s&) const\n");
        using Fn = void * (*)(rmw_qos_incompatible_event_status_s&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp16SubscriptionBase33default_incompatible_qos_callbackER35rmw_qos_incompatible_event_status_s");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real(a0);
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZNK6rclcpp16SubscriptionBase36matches_any_intra_process_publishersEPK9rmw_gid_s_wrapper(rmw_gid_s const* a0)
    {
        //wakka printf[WRAP] rclcpp::SubscriptionBase::matches_any_intra_process_publishers(rmw_gid_s const*) const\n");
        using Fn = void * (*)(rmw_gid_s const*);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp16SubscriptionBase36matches_any_intra_process_publishersEPK9rmw_gid_s");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real(a0);
        mpk_exit_gate();
        return ret;
    }

#include <vector>
#include <rclcpp/qos_overriding_options.hpp>   // adjust include to where QosOverridingOptions lives

// extern "C"
// void _ZNK6rclcpp20QosOverridingOptions16get_policy_kindsEv(
//     void *ret,
//     const void *self)
// {
//     //wakka printf[WRAP] rclcpp::QosOverridingOptions::get_policy_kinds() const\n");

//     using Vec = std::vector<rclcpp::QosPolicyKind>;
//     using Fn  = void (*)(Vec*, const void*);

//     static Fn real = nullptr;

//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//             "_ZNK6rclcpp20QosOverridingOptions16get_policy_kindsEv");
//         if (!real) abort();
//     }
//   // mpk_entry_gate();
//     real(reinterpret_cast<Vec*>(ret), self);
//     //mpk_exit_gate();
// }


    extern "C"
    void * _ZNK6rclcpp20QosOverridingOptions23get_validation_callbackEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QosOverridingOptions::get_validation_callback() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp20QosOverridingOptions23get_validation_callbackEv");
            if (!real) abort();
        }
        return real();
    }

    extern "C"
    void * _ZNK6rclcpp20QosOverridingOptions6get_idB5cxx11Ev_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QosOverridingOptions::get_id[abi:cxx11]() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp20QosOverridingOptions6get_idB5cxx11Ev");
            if (!real) abort();
        }
        mpk_entry_gate();
        return real();
        mpk_exit_gate();    
    }

    extern "C"
    void * _ZNK6rclcpp3QoS10durabilityEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QoS::durability() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp3QoS10durabilityEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZNK6rclcpp3QoS19get_rmw_qos_profileEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QoS::get_rmw_qos_profile() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp3QoS19get_rmw_qos_profileEv");
            if (!real) abort();
        }
        return real();
    }

    extern "C"
    void * _ZNK6rclcpp3QoS5depthEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QoS::depth() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp3QoS5depthEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret =  real();
        mpk_exit_gate();
        return ret;
    }

    extern "C"
    void * _ZNK6rclcpp3QoS7historyEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::QoS::history() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp3QoS7historyEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real();
        mpk_exit_gate();
        return ret;
    }

  #include <rclcpp/logger.hpp>

extern "C"
void _ZNK6rclcpp4Node10get_loggerEv(
    void *ret,
    const void *self)
{
    //wakka printf[WRAP] rclcpp::Node::get_logger() const\n");

    using Logger = rclcpp::Logger;
    using Fn = void (*)(Logger*, const void*);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZNK6rclcpp4Node10get_loggerEv");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(reinterpret_cast<Logger*>(ret), self);
    mpk_exit_gate();
}


//   extern "C"
// void _ZNK6rclcpp4Node17get_sub_namespaceB5cxx11Ev_wrapper(
//     void *ret,
//     const void *self)
// {
//     //wakka printf[WRAP] rclcpp::Node::get_sub_namespace() const\n");

//     using Fn = void (*)(void*, const void*);
//     static Fn real = nullptr;

//     if (!real) {
//         real = (Fn)dlsym(RTLD_NEXT,
//             "_ZNK6rclcpp4Node17get_sub_namespaceB5cxx11Ev");
//         if (!real) abort();
//     }
//     //mpk_entry_gate();
//     real(ret, self);
//     //mpk_exit_gate();    
// }


    // extern "C"
    // void * _ZNK6rclcpp4Time11nanosecondsEv_wrapper()
    // {
    //     //wakka printf[WRAP] rclcpp::Time::nanoseconds() const\n");
    //     using Fn = void * (*)();
    //     static Fn real = nullptr;
    //     if (!real) {
    //         real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp4Time11nanosecondsEv");
    //         if (!real) abort();
    //     }

    //     mpk_entry_gate();
    //     void * ret = real();
    //     mpk_exit_gate();
    //     return ret; 
    // }

   extern "C"
builtin_interfaces::msg::Time_<std::allocator<void>>
_ZNK6rclcpp4TimecvN18builtin_interfaces3msg5Time_ISaIvEEEEv_wrapper(
    const rclcpp::Time* self)
{
    //wakka printf[WRAP] rclcpp::Time::operator builtin_interfaces::msg::Time_<Allocator>() const\n");

    using Ret = builtin_interfaces::msg::Time_<std::allocator<void>>;
    using Fn  = Ret (*)(const rclcpp::Time*);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZNK6rclcpp4TimecvN18builtin_interfaces3msg5Time_ISaIvEEEEv"
        );
        if (!real) abort();
    }

    return real(self);
}
    // extern "C"
    // void * _ZNK6rclcpp5Clock14get_clock_typeEv_wrapper()
    // {
    //     //wakka printf[WRAP] rclcpp::Clock::get_clock_type() const\n");
    //     using Fn = void * (*)();
    //     static Fn real = nullptr;
    //     if (!real) {
    //         real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp5Clock14get_clock_typeEv");
    //         if (!real) abort();
    //     }
    //     mpk_entry_gate();
    //     void * ret = real();
    //     mpk_exit_gate();
    //     return ret;
    // }

    extern "C"
    void * _ZNK6rclcpp6detail32RMWImplementationSpecificPayload19has_been_customizedEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::detail::RMWImplementationSpecificPayload::has_been_customized() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp6detail32RMWImplementationSpecificPayload19has_been_customizedEv");
            if (!real) abort();
        }
        mpk_entry_gate();  
        void * ret = real();
        mpk_exit_gate();
        return ret;
    }

    // extern "C"
    // void * _ZNK6rclcpp8Duration11nanosecondsEv_wrapper()
    // {
    //     //wakka printf[WRAP] rclcpp::Duration::nanoseconds() const\n");
    //     using Fn = void * (*)();
    //     static Fn real = nullptr;
    //     if (!real) {
    //         real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp8Duration11nanosecondsEv");
    //         if (!real) abort();
    //     }
    //     mpk_entry_gate();
    //     void * ret =  real();
    //     mpk_exit_gate();
    //     return ret;
    // }

    extern "C"
    void * _ZNK6rclcpp9Parameter19get_parameter_valueEv_wrapper()
    {
        //wakka printf[WRAP] rclcpp::Parameter::get_parameter_value() const\n");
        using Fn = void * (*)();
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNK6rclcpp9Parameter19get_parameter_valueEv");
            if (!real) abort();
        }
        mpk_entry_gate();
        void * ret = real();
        mpk_exit_gate();
        return ret;
    }

  extern "C"
std::allocator<char>
_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13get_allocatorEv_wrapper(
    const std::string* self)
{
    //wakka printf[WRAP] std::string::get_allocator() const\n");

    using Fn =
        std::allocator<char> (*)(const std::string*);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13get_allocatorEv");
        if (!real) abort();
    }

    return real(self);
}
#include <string>
#include <sstream>
#include <dlfcn.h>
#include <stdio.h>

// ----------------------------------------------------------
// size() const
// ----------------------------------------------------------
extern "C"
size_t
_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv_wrapper(
    const std::string* self)
{
    //wakka printf[WRAP] std::string::size() const\n");

    using Fn = size_t (*)(const std::string*);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT,
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv");

    return real(self);
}

// ----------------------------------------------------------
// c_str() const
// ----------------------------------------------------------
// extern "C"
// const char*
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv_wrapper(
//     const std::string* self)
// {
//     //wakka printf[WRAP] std::string::c_str() const\n");

//     using Fn = const char* (*)(const std::string*);
//     static Fn real = nullptr;
//     if (!real) real = (Fn)dlsym(RTLD_NEXT,
//         "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv");

//     return real(self);
// }

// ----------------------------------------------------------
// empty() const
// ----------------------------------------------------------
extern "C"
bool
_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5emptyEv_wrapper(
    const std::string* self)
{
    //wakka printf[WRAP] std::string::empty() const\n");

    using Fn = bool (*)(const std::string*);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT,
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5emptyEv");

    return real(self);
}

// ----------------------------------------------------------
// front() const
// ----------------------------------------------------------
// extern "C"
// char
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5frontEv_wrapper(
//     const std::string* self)
// {
//     //wakka printf[WRAP] std::string::front() const\n");

//     using Fn = char (*)(const std::string*);
//     static Fn real = nullptr;
//     if (!real) real = (Fn)dlsym(RTLD_NEXT,
//         "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5frontEv");

//     return real(self);
// }

// ----------------------------------------------------------
// _M_data() const → points to internal buffer
// ----------------------------------------------------------
// extern "C"
// const char*
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv_wrapper(
//     const std::string* self)
// {
//     //wakka printf[WRAP] std::string::_M_data() const\n");

//     using Fn = const char* (*)(const std::string*);
//     static Fn real = nullptr;
//     if (!real) real = (Fn)dlsym(RTLD_NEXT,
//         "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv");

//     return real(self);
// }

// ----------------------------------------------------------
// compare(char const*) const
// ----------------------------------------------------------
// extern "C"
// int
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc_wrapper(
//     const std::string* self,
//     const char* s)
// {
//     //wakka printf[WRAP] std::string::compare(char const*) const\n");

//     using Fn = int (*)(const std::string*, const char*);
//     static Fn real = nullptr;
//     if (!real) real = (Fn)dlsym(RTLD_NEXT,
//         "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc");

//     return real(self, s);
// }

// ----------------------------------------------------------
// capacity() const
// ----------------------------------------------------------
extern "C"
size_t
_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv_wrapper(
    const std::string* self)
{
    //wakka printf[WRAP] std::string::capacity() const\n");

    using Fn = size_t (*)(const std::string*);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT,
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE8capacityEv");

    return real(self);
}

// ----------------------------------------------------------
// stringstream::str() const
// ----------------------------------------------------------
extern "C"
std::string
_ZNKSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEE3strEv_wrapper(
    const std::stringstream* self)
{
    //wakka printf[WRAP] std::stringstream::str() const\n");

    using Fn = std::string (*)(const std::stringstream*);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT,
        "_ZNKSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEE3strEv");

    return real(self);
}

// ----------------------------------------------------------
// ostringstream::str() const
// ----------------------------------------------------------
extern "C"
std::string
_ZNKSt7__cxx1119basic_ostringstreamIcSt11char_traitsIcESaIcEE3strEv_wrapper(
    const std::ostringstream* self)
{
    //wakka printf[WRAP] std::ostringstream::str() const\n");

    using Fn = std::string (*)(const std::ostringstream*);
    static Fn real = nullptr;
    if (!real) real = (Fn)dlsym(RTLD_NEXT,
        "_ZNKSt7__cxx1119basic_ostringstreamIcSt11char_traitsIcESaIcEE3strEv");

    return real(self);
}

    // extern "C"
    // void * _ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEmmm_wrapper(unsigned long a0, unsigned long a1, unsigned long a2)
    // {
    //     //wakka printf[WRAP] std::__detail::_Prime_rehash_policy::_M_need_rehash(unsigned long, unsigned long, unsigned long) const\n");
    //     using Fn = void * (*)(unsigned long, unsigned long, unsigned long);
    //     static Fn real = nullptr;
    //     if (!real) {
    //         real = (Fn)dlsym(RTLD_NEXT, "_ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEmmm");
    //         if (!real) abort();
    //     }
    //     return real(a0, a1, a2);
    // }

    extern "C"
    void * _ZNSaIcEC1ERKS__wrapper(std::allocator<char> const& a0)
    {
        //wakka printf[WRAP] std::allocator<char>::allocator(std::allocator<char> const&)\n");
        using Fn = void * (*)(std::allocator<char> const&);
        static Fn real = nullptr;
        if (!real) {
            real = (Fn)dlsym(RTLD_NEXT, "_ZNSaIcEC1ERKS_");
            if (!real) abort();
        }
        return real(a0);
    }


#include <string>
#include <dlfcn.h>
#include <stdio.h>






//
// 4️⃣ _M_construct(size_t, char)
//     Initializes N chars → void return
//
extern "C"
void
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEmc_wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
    unsigned long n,
    char c)
{
    //wakka printf[WRAP] std::string::_M_construct(%lu, '%c')\n", n, c);

    using Fn =
        void (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
                 unsigned long,
                 char);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructEmc");
        if (!real) abort();
    }
    real(self, n, c);
}







//
// ===== std::string::insert(size_t, const string&) =====
//
extern "C"
std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6insertEmRKS4__wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
    unsigned long pos,
    const std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>& s)
{
    //wakka printf[WRAP] std::string::insert(pos=%lu, string&)\n", pos);

    using Fn =
        std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&
        (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
            unsigned long,
            const std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6insertEmRKS4_");
        if (!real) abort();
    }

    return real(self, pos, s);
}
//
// ===== std::string::reserve(size_t) =====
//
extern "C"
void
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7reserveEm_wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
    unsigned long capacity)
{
    //wakka printf[WRAP] std::string::reserve(%lu)\n", capacity);

    using Fn =
        void (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
                 unsigned long);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7reserveEm");
        if (!real) abort();
    }

    real(self, capacity);
}


//


// ===== std::string::basic_string(std::allocator<char> const&)   (C1ERKS3_) =====
//
extern "C"
void
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS3__wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
    const std::allocator<char>& alloc)
{
    //wakka printf[WRAP] std::string ctor(this=%p, allocator)\n", self);

    using Fn =
        void (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
                 const std::allocator<char>&);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS3_");
        if (!real) abort();
    }

    real(self, alloc);
}



// ===== std::string default constructor  (C1Ev) =====
extern "C"
void
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev_wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self)
{
    //wakka printf[WRAP] std::string::basic_string() this=%p\n", self);

    using Fn =
        void (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev");
        if (!real) {
            fprintf(stderr, "ERROR resolving std::string C1Ev constructor\n");
            abort();
        }
    }

    real(self);
}



  extern "C"
std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc_wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
    const char* rhs)
{
    //wakka printf[WRAP] std::string::operator=(this=%p, \"%s\")\n", self, rhs ? rhs : "(null)");

    using Fn =
        std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&
        (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
            const char*);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc");
        if (!real) {
            fprintf(stderr, "ERROR resolving std::string::operator=(char const*)\n");
            abort();
        }
    }

    return real(self, rhs);
}

extern "C"
char&
_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm_wrapper(
    std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
    unsigned long index)
{
    //wakka printf[WRAP] std::string::operator[](this=%p, index=%lu)\n", self, index);

    using Fn =
        char& (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
                  unsigned long);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm");
        if (!real) {
            fprintf(stderr, "ERROR resolving std::string::operator[]\n");
            abort();
        }
    }

    return real(self, index);
}


// extern "C"
// char&
// _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm_wrapper(
//     std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>* self,
//     size_t index)
// {
//     //wakka printf[WRAP] std::string::operator[](this=%p, index=%zu)\n", self, index);

//     using Fn =
//         char& (*)(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>*,
//                   size_t);

//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(RTLD_NEXT,
//             "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm");
//         if (!real) {
//             fprintf(stderr, "ERROR resolving std::string::operator[]\n");
//             abort();
//         }
//     }

//     return real(self, index);
// }


// ========= basic_stringstream<char>::~basic_stringstream() (D1) =========
extern "C"
void
_ZNSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEED1Ev_wrapper(
    std::__cxx11::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>* self)
{
    //wakka printf[WRAP] ~basic_stringstream(%p)\n", self);

    using Fn =
        void (*)(std::__cxx11::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>*);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1118basic_stringstreamIcSt11char_traitsIcESaIcEED1Ev");
        if (!real) {
            fprintf(stderr, "ERROR resolving ~basic_stringstream\n");
            abort();
        }
    }

    real(self);
}


// ========= basic_ostringstream<char>::basic_ostringstream(string, mode) (C1) =========
extern "C"
void
_ZNSt7__cxx1119basic_ostringstreamIcSt11char_traitsIcESaIcEEC1ERKNS_12basic_stringIcS2_S3_EESt13_Ios_Openmode_wrapper(
    std::__cxx11::basic_ostringstream<char, std::char_traits<char>, std::allocator<char>>* self,
    const std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>& a0,
    std::_Ios_Openmode a1)
{
    //wakka printf[WRAP] basic_ostringstream(this=%p, string, mode=%d)\n", self, (int)a1);

    using Fn =
        void (*)(std::__cxx11::basic_ostringstream<char, std::char_traits<char>, std::allocator<char>>*,
                 const std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&,
                 std::_Ios_Openmode);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
            "_ZNSt7__cxx1119basic_ostringstreamIcSt11char_traitsIcESaIcEEC1ERKNS_12basic_stringIcS2_S3_EESt13_Ios_Openmode");
        if (!real) {
            fprintf(stderr, "ERROR resolving basic_ostringstream C1\n");
            abort();
        }
    }

    real(self, a0, a1);
}




// ===== std::string::_Alloc_hider::Alloc_hider(char*, const allocator&) =====
//


#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <rcl/rcl.h>
#include <rcl/event.h>
#include <rcl/publisher.h>
#include <rcl/subscription.h>

#include <dlfcn.h>

// rcutils
#include <rcutils/allocator.h>
#include <rcutils/logging.h>
#include <rcutils/error_handling.h>

// rmw QoS
#include <rmw/qos_profiles.h>
#include <rmw/qos_policy_kind.h>



extern "C"
bool rcl_context_is_valid_wrapper(const rcl_context_t * context)
{
    //wakka printf[WRAP] rcl_context_is_valid()\n");
    using Fn = bool (*)(const rcl_context_t *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_context_is_valid");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real(context);
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_event_t rcl_get_zero_initialized_event_wrapper()
{
    //wakka printf[WRAP] rcl_get_zero_initialized_event()\n");
    using Fn = rcl_event_t (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_get_zero_initialized_event");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real();
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_guard_condition_options_t rcl_guard_condition_get_default_options_wrapper()
{
    //wakka printf[WRAP] rcl_guard_condition_get_default_options()\n");
    using Fn = rcl_guard_condition_options_t (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_guard_condition_get_default_options");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real();
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_ret_t rcl_publish_wrapper(
    const rcl_publisher_t * publisher,
    const void * ros_message,
    void * allocation)
{
    //wakka printf[WRAP] rcl_publish()\n");
    using Fn = rcl_ret_t (*)(const rcl_publisher_t *, const void *, void *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_publish");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret = real(publisher, ros_message, allocation);
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_context_t * rcl_publisher_get_context_wrapper(const rcl_publisher_t * publisher)
{
    //wakka printf[WRAP] rcl_publisher_get_context()\n");
    using Fn = rcl_context_t * (*)(const rcl_publisher_t *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_publisher_get_context");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real(publisher);
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_publisher_options_t rcl_publisher_get_default_options_wrapper()
{
    //wakka printf[WRAP] rcl_publisher_get_default_options()\n");
    using Fn = rcl_publisher_options_t (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_publisher_get_default_options");
        if (!real) abort();
    }
    mpk_entry_gate();  
    auto ret =  real();
    mpk_exit_gate();
    return ret;
}

extern "C"
bool rcl_publisher_is_valid_except_context_wrapper(const rcl_publisher_t * publisher)
{
    //wakka printf[WRAP] rcl_publisher_is_valid_except_context()\n");
    using Fn = bool (*)(const rcl_publisher_t *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_publisher_is_valid_except_context");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real(publisher);
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_subscription_options_t rcl_subscription_get_default_options_wrapper()
{
    //wakka printf[WRAP] rcl_subscription_get_default_options()\n");
    using Fn = rcl_subscription_options_t (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_subscription_get_default_options");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real();
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_ret_t rcl_subscription_options_set_content_filter_options_wrapper(
    rcl_subscription_options_t * options,
    const rcl_subscription_content_filter_options_t * filter_options)
{
    //wakka printf[WRAP] rcl_subscription_options_set_content_filter_options()\n");
    using Fn = rcl_ret_t (*)(rcl_subscription_options_t *,
                             const rcl_subscription_content_filter_options_t *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
                         "rcl_subscription_options_set_content_filter_options");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real(options, filter_options);
    mpk_exit_gate();
    return ret;
}

extern "C"
rcl_ret_t rcl_take_event_wrapper(
    const rcl_event_t * event_handle,
    void * event_info,
    size_t * taken)
{
    //wakka printf[WRAP] rcl_take_event()\n");
    using Fn = rcl_ret_t (*)(const rcl_event_t *, void *, size_t *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_take_event");
        if (!real) abort();
    }
    mpk_entry_gate();  
    auto ret = real(event_handle, event_info, taken);
    mpk_exit_gate();
    return ret; 
}


extern "C"
const rcutils_error_state_t * rcutils_get_error_state_wrapper()
{
    using Fn = const rcutils_error_state_t *(*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcutils_get_error_state");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret = real();
    mpk_exit_gate();
    return ret;
}


extern "C"
rcutils_error_string_t rcutils_get_error_string_wrapper()
{
    using Fn = rcutils_error_string_t (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcutils_get_error_string");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret = real();
    mpk_exit_gate();
    return ret;
}


// extern "C"
// void rcutils_log_wrapper(
//     const rcutils_log_location_t * location,
//     int severity,
//     const char * name,
//     rcutils_time_point_value_t timestamp,
//     const char * format, ...)
// {
//     using Fn = void (*)(const rcutils_log_location_t *, int,
//                         const char *, rcutils_time_point_value_t,
//                         const char *, ...);
//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(RTLD_NEXT, "rcutils_log");
//         if (!real) abort();
//     }
//     mpk_entry_gate();
//     va_list args;
//     va_start(args, format);
//     real(location, severity, name, timestamp, format, args);
//     va_end(args);
//     mpk_exit_gate();
// }


extern "C"
rcutils_ret_t rcutils_logging_initialize_wrapper()
{
    using Fn = rcutils_ret_t (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcutils_logging_initialize");
        if (!real) abort();
    }
    mpk_entry_gate();
    auto ret =  real();
    mpk_exit_gate();
    return ret;
}


extern "C"
bool rcutils_logging_logger_is_enabled_for_wrapper(
    const char * name,
    int severity)
{
    using Fn = bool (*)(const char *, int);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT,
                         "rcutils_logging_logger_is_enabled_for");
        if (!real) abort();
    }

    mpk_entry_gate();
    auto ret =  real(name, severity);
    mpk_exit_gate();
    return ret;
}





#include <rmw/qos_policy_kind.h>
#include <dlfcn.h>








extern "C"
void ros_trace_callback_end_wrapper()
{
    using Fn = void (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "ros_trace_callback_end");
        if (!real) abort();
    }
    mpk_entry_gate();
    real();
    mpk_exit_gate();
}

extern "C"
void ros_trace_callback_start_wrapper()
{
    using Fn = void (*)();
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "ros_trace_callback_start");
        if (!real) abort();
    }
    mpk_entry_gate();
    real();
    mpk_exit_gate();
}


extern "C"
void ros_trace_rclcpp_callback_register_wrapper(const void * callback)
{
    using Fn = void (*)(const void *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "ros_trace_rclcpp_callback_register");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(callback);
    mpk_exit_gate();
}

extern "C"
void ros_trace_rclcpp_publish_wrapper(
    const void * pub,
    const void * msg)
{
    using Fn = void (*)(const void *, const void *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "ros_trace_rclcpp_publish");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(pub, msg);
    mpk_exit_gate();
}

extern "C"
void ros_trace_rclcpp_subscription_callback_added_wrapper(
    const void * sub)
{
    using Fn = void (*)(const void *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "ros_trace_rclcpp_subscription_callback_added");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(sub);
    mpk_exit_gate();
}

extern "C"
void ros_trace_rclcpp_subscription_init_wrapper(const void * sub)
{
    using Fn = void (*)(const void *);
    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "ros_trace_rclcpp_subscription_init");
        if (!real) abort();
    }
    mpk_entry_gate();
    real(sub);
    mpk_exit_gate();
}

// extern "C"
// void ros_trace_rclcpp_timer_callback_added_wrapper(
//     const void * timer)
// {
//     using Fn = void (*)(const void *);
//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(RTLD_NEXT, "ros_trace_rclcpp_timer_callback_added");
//         if (!real) abort();
//     }
//     mpk_entry_gate();
//     real(timer);
//     mpk_exit_gate();
// }

// extern "C"
// void
// _ZN6rclcpp11InitOptionsC1E19rcutils_allocator_s_wrapper(
//     void * self,
//     rcutils_allocator_s a0)
// {
//     using Fn = void (*)(void *, rcutils_allocator_s);

//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//               "_ZN6rclcpp11InitOptionsC1E19rcutils_allocator_s"
//         );
//         if (!real) abort();
//     }

//     // NO mpk_entry_gate() here
//     mpk_entry_gate();
//     real(self, a0);
//     mpk_exit_gate();
//     // NO mpk_exit_gate()
// }

extern "C"
void
_ZN23libstatistics_collector9collector9Collector10AcceptDataEd_wrapper(
    void * self,
    double a0)
{
    using Fn = void (*)(void *, double);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN23libstatistics_collector9collector9Collector10AcceptDataEd"
        );
        if (!real) abort();
    }

    mpk_entry_gate();
    real(self, a0);
    mpk_exit_gate();
}

// extern "C"
// void *
// _ZN10tracetools6detail18get_symbol_funcptrEPv_wrapper(void * a0)
// {
//     using Fn = void * (*)(void *);
//     static Fn real = nullptr;

//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//             "_ZN10tracetools6detail18get_symbol_funcptrEPv"
//         );
//         if (!real) abort();
//     }

//     mpk_entry_gate();
//     void * ret = real(a0);
//     mpk_exit_gate();

//     return ret;
// }



extern "C"
void
_ZN6rclcpp9executors21MultiThreadedExecutor4spinEv_wrapper(void * a0)
{
    using Fn = void (*)(void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9executors21MultiThreadedExecutor4spinEv"
        );
        if (!real)
            abort();
    }

    mpk_entry_gate();
    real(a0);
    mpk_exit_gate();
}



extern "C"
void
_ZN6rclcpp9executors21MultiThreadedExecutorC1ERKNS_15ExecutorOptionsEmbNSt6chrono8durationIlSt5ratioILl1ELl1000000000EEEE_wrapper(
    void * a0,   // this
    void * a1,   // const rclcpp::ExecutorOptions &
    bool  a2,    // bool
    unsigned long a3, // number of threads
    void * a4    // std::chrono::nanoseconds
)
{
    using Fn = void (*)(void *, void *, bool, unsigned long, void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9executors21MultiThreadedExecutorC1ERKNS_15ExecutorOptionsEmbNSt6chrono8durationIlSt5ratioILl1ELl1000000000EEEE"
        );
        if (!real)
            abort();
    }

    mpk_entry_gate();
    real(a0, a1, a2, a3, a4);
    mpk_exit_gate();
}


extern "C"
void
_ZN6rclcpp9executors21MultiThreadedExecutorD1Ev_wrapper(void * a0)
{
    using Fn = void (*)(void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp9executors21MultiThreadedExecutorD1Ev"
        );
        if (!real)
            abort();
    }

    mpk_entry_gate();
    real(a0);
    mpk_exit_gate();
}   





#include <dlfcn.h>
#include <cstdlib>

/* Your hooks */
void mpk_entry_gate();
void mpk_exit_gate();

/* -------------------------------------------------- */
/* rclcpp::Node::get_clock()                           */
/* -------------------------------------------------- */
extern "C"
void *
_ZN6rclcpp4Node9get_clockEv_wrapper(void *a0)
{
    using Fn = void *(*)(void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp4Node9get_clockEv"
        );
        if (!real)
            abort();
    }

    mpk_entry_gate();
    void *ret = real(a0);
    mpk_exit_gate();

    return ret;
}

/* -------------------------------------------------- */
/* rclcpp::spin(std::shared_ptr<rclcpp::Node>)        */
/* -------------------------------------------------- */
extern "C"
void
_ZN6rclcpp4spinESt10shared_ptrINS_4NodeEE_wrapper(void *a0)
{
    using Fn = void (*)(void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp4spinESt10shared_ptrINS_4NodeEE"
        );
        if (!real)
            abort();
    }

    mpk_entry_gate();
    real(a0);
    mpk_exit_gate();
}

/* -------------------------------------------------- */
/* rclcpp::Clock::now()                               */
/* -------------------------------------------------- */
extern "C"
void *
_ZN6rclcpp5Clock3nowEv_wrapper(void *a0)
{
    using Fn = void *(*)(void *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp5Clock3nowEv"
        );
        if (!real)
            abort();
    }

    mpk_entry_gate();
    void *ret = real(a0);
    mpk_exit_gate();

    return ret;
}



#include <dlfcn.h>
#include <cstdlib>

#include "rosidl_runtime_c/service_type_support_struct.h"

extern "C"
const rosidl_service_type_support_t *
_ZN22rosidl_typesupport_cpp31get_service_type_support_handleIN13benchmark_pkg3srv3FibEEEPK29rosidl_service_type_support_t_wrapper()
{
    using Fn = const rosidl_service_type_support_t * (*)();

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN22rosidl_typesupport_cpp31get_service_type_support_handleIN13benchmark_pkg3srv3FibEEEPK29rosidl_service_type_support_t"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();
    const rosidl_service_type_support_t * ret = real();
    mpk_exit_gate();

    return ret;
}

#include <dlfcn.h>
#include <cstdlib>
#include <memory>

#include "rcl/client.h"   // rcl_client_t

extern "C"
std::shared_ptr<rcl_client_t>
_ZN6rclcpp10ClientBase17get_client_handleEv_wrapper()
{
    using Fn = std::shared_ptr<rcl_client_t> (*)();

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp10ClientBase17get_client_handleEv"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();
    auto ret = real();
    mpk_exit_gate();

    return ret;
}


#include <dlfcn.h>
#include <cstdlib>
#include <memory>

#include "rcl/node.h"   // rcl_node_t

// extern "C"
// std::shared_ptr<rcl_node_t>
// _ZN6rclcpp10ClientBase19get_rcl_node_handleEv_wrapper()
// {
//     using Fn = std::shared_ptr<rcl_node_t> (*)();

//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//             "_ZN6rclcpp10ClientBase19get_rcl_node_handleEv"
//         );
//         if (!real) {
//             abort();
//         }
//     }

//     mpk_entry_gate();
//     auto ret = real();
//     mpk_exit_gate();

//     return ret;
// }


#include <dlfcn.h>
#include <cstdlib>
#include <chrono>

extern "C"
bool
_ZN6rclcpp10ClientBase28wait_for_service_nanosecondsENSt6chrono8durationIlSt5ratioILl1ELl1000000000EEEE_wrapper(
    std::chrono::nanoseconds timeout)
{
    using Fn = bool (*)(std::chrono::nanoseconds);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp10ClientBase28wait_for_service_nanosecondsENSt6chrono8durationIlSt5ratioILl1ELl1000000000EEEE"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();
    bool ret = real(timeout);
    mpk_exit_gate();

    return ret;
}

#include <dlfcn.h>
#include <cstdlib>
#include <memory>

#include "rclcpp/node_interfaces/node_base_interface.hpp"
#include "rclcpp/node_interfaces/node_graph_interface.hpp"

extern "C"
void
_ZN6rclcpp10ClientBaseC2EPNS_15node_interfaces17NodeBaseInterfaceESt10shared_ptrINS1_18NodeGraphInterfaceEE_wrapper(
    void * this_ptr,
    rclcpp::node_interfaces::NodeBaseInterface * node_base,
    std::shared_ptr<rclcpp::node_interfaces::NodeGraphInterface> node_graph)
{
    using Fn = void (*)(
        void *,
        rclcpp::node_interfaces::NodeBaseInterface *,
        std::shared_ptr<rclcpp::node_interfaces::NodeGraphInterface>
    );

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp10ClientBaseC2EPNS_15node_interfaces17NodeBaseInterfaceESt10shared_ptrINS1_18NodeGraphInterfaceEE"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();
    real(this_ptr, node_base, node_graph);
    mpk_exit_gate();
}



#include <dlfcn.h>
#include <cstdlib>

extern "C"
void
_ZN6rclcpp10ClientBaseD2Ev_wrapper(void * this_ptr)
{
    using Fn = void (*)(void *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp10ClientBaseD2Ev"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();     // your instrumentation
    real(this_ptr);
    mpk_exit_gate();
}

// #include <dlfcn.h>
// #include <cstdlib>

// #include "rcutils/allocator.h"

// extern "C"
// void
// _ZN6rclcpp11NodeOptionsC1E19rcutils_allocator_s_wrapper(
//     void * this_ptr,
//     rcutils_allocator_s allocator)
// {
//     using Fn = void (*)(void *, rcutils_allocator_s);

//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//             "_ZN6rclcpp11NodeOptionsC1E19rcutils_allocator_s"
//         );
//         if (!real) {
//             abort();
//         }
//     }

//     mpk_entry_gate();   // your instrumentation
//     real(this_ptr, allocator);
//     mpk_exit_gate();
// }



#include <dlfcn.h>
#include <cstdlib>
#include <memory>

#include "rclcpp/node.hpp"
#include "rclcpp/callback_group.hpp"

extern "C"
std::shared_ptr<rclcpp::CallbackGroup>
_ZN6rclcpp4Node21create_callback_groupENS_17CallbackGroupTypeEb_wrapper(
    rclcpp::Node * this_ptr,
    rclcpp::CallbackGroupType group_type,
    bool auto_add)
{
    using Fn = std::shared_ptr<rclcpp::CallbackGroup> (*)(
        rclcpp::Node *,
        rclcpp::CallbackGroupType,
        bool
    );

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp4Node21create_callback_groupENS_17CallbackGroupTypeEb"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();   // your instrumentation

    auto ret = real(this_ptr, group_type, auto_add);

    mpk_exit_gate();
    return ret;
}





#include <pthread.h>
#include <dlfcn.h>
#include <cstdlib>

extern "C"
int pthread_once_wrapper(
    pthread_once_t * once_control,
    void (*init_routine)(void))
{
    using Fn = int (*)(pthread_once_t *, void (*)(void));
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "pthread_once");
        if (!real) abort();
    }

    /* ⚠️ CRITICAL:
     * This may be called while holding locks.
     * NO printf / malloc / locks here.
     */

    // mpk_entry_gate();   // must be TLS or lock-free

    int ret = real(once_control, init_routine);

    // mpk_exit_gate();

    return ret;
}


#include <rcl/client.h>
#include <dlfcn.h>
#include <cstdlib>

extern "C"
rcl_ret_t rcl_client_init_wrapper(
    rcl_client_t * client,
    const rcl_node_t * node,
    const rosidl_service_type_support_t * type_support,
    const char * service_name,
    const rcl_client_options_t * options)
{
    using Fn = rcl_ret_t (*)(rcl_client_t *,
                             const rcl_node_t *,
                             const rosidl_service_type_support_t *,
                             const char *,
                             const rcl_client_options_t *);

    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_client_init");
        if (!real) abort();
    }

    /* ⚠️ Do NOT log / allocate / lock here */

    mpk_entry_gate();   // must be TLS or lock-free

    rcl_ret_t ret = real(client, node, type_support, service_name, options);

    mpk_exit_gate();

    return ret;
}

#include <rcl/node.h>
#include <dlfcn.h>
#include <cstdlib>

extern "C"
const char *
rcl_node_get_name_wrapper(const rcl_node_t * node)
{
    using Fn = const char * (*)(const rcl_node_t *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_node_get_name");
        if (!real) abort();
    }

    /* Safe accessor, but still:
     * NO logging here to avoid recursion
     */

    mpk_entry_gate();   // TLS / lock-free

    const char * ret = real(node);

    mpk_exit_gate();

    return ret;
}

#include <rcl/node.h>
#include <dlfcn.h>
#include <cstdlib>

extern "C"
const char *
rcl_node_get_namespace_wrapper(const rcl_node_t * node)
{
    using Fn = const char * (*)(const rcl_node_t *);
    static Fn real = nullptr;

    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_node_get_namespace");
        if (!real) abort();
    }

    /* IMPORTANT:
     * Do NOT log or allocate here.
     * This function is often called from logging paths.
     */

    mpk_entry_gate();   // TLS / lock-free only

    const char * ret = real(node);

    mpk_exit_gate();

    return ret;
}

#include <rcl/client.h>
#include <dlfcn.h>
#include <cstdlib>

extern "C"
rcl_ret_t
rcl_send_request(
    const rcl_client_t * client,
    const void * ros_request,
    int64_t * sequence_number)
{
    using Fn = rcl_ret_t (*)(const rcl_client_t *,
                             const void *,
                             int64_t *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_send_request");
        if (!real) abort();
    }

    mpk_entry_gate();   // MUST be lock-free / TLS only

    rcl_ret_t ret = real(client, ros_request, sequence_number);

    mpk_exit_gate();

    return ret;
}


#include <dlfcn.h>
#include <cstdlib>

#include <rosidl_runtime_c/service_type_support_struct.h>
#include <dlfcn.h>
#include <cstdlib>

struct rosidl_service_type_support_t;

extern "C"
void *
_ZN22rosidl_typesupport_cpp31get_service_type_support_handleIN13benchmark_pkg3srv3FibEEEPK29rosidl_service_type_support_tv_wrapper()
{
    using Fn = const rosidl_service_type_support_t * (*)();

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN22rosidl_typesupport_cpp31get_service_type_support_handleIN13benchmark_pkg3srv3FibEEEPK29rosidl_service_type_support_tv"
        );
        if (!real) abort();
    }

    mpk_entry_gate();
    const rosidl_service_type_support_t * ret = real();
    mpk_exit_gate();

    return (void *)ret;
}

#include <dlfcn.h>
#include <cstdlib>

// struct rcutils_error_state_s;
// extern "C"
// void
// _ZN6rclcpp10exceptions20throw_from_rcl_errorEiRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPK21rcutils_error_state_sPFvvE_wrapper(
//     int error_code,
//     const std::string & prefix,
//     const rcutils_error_state_s * error_state,
//     void (* reset_error_fn)(void))
// {
//     using Fn =
//       void (*)(int,
//                const std::string &,
//                const rcutils_error_state_s *,
//                void (*)(void));

//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(
//             RTLD_NEXT,
//             "_ZN6rclcpp10exceptions20throw_from_rcl_errorEiRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPK21rcutils_error_state_sPFvvE"
//         );
//         if (!real) {
//             abort();
//         }
//     }

//     mpk_entry_gate();

//     // ⚠️ This function may throw and never return
//     real(error_code, prefix, error_state, reset_error_fn);

//     mpk_exit_gate();
// }

#include <dlfcn.h>
#include <cstdlib>


extern "C"
void
_ZN6rclcpp11ServiceBase16get_service_nameEv_wrapper(
    std::string * ret,
    void * this_ptr)
{
    using Fn = void (*)(std::string *, void *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp11ServiceBase16get_service_nameEv"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    real(ret, this_ptr);

    mpk_exit_gate();
}


#include <dlfcn.h>
#include <cstdlib>


extern "C"
rcl_node_t *
_ZN6rclcpp11ServiceBase19get_rcl_node_handleEv_wrapper(
    void * this_ptr)
{
    using Fn = rcl_node_t * (*)(void *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp11ServiceBase19get_rcl_node_handleEv"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    rcl_node_t * ret = real(this_ptr);

    mpk_exit_gate();

    return ret;
}


#include <dlfcn.h>
#include <cstdlib>


extern "C"
void
_ZN6rclcpp11ServiceBaseC2ESt10shared_ptrI10rcl_node_sE_wrapper(
    void * this_ptr,
    std::shared_ptr<rcl_node_s> node_handle)
{
    using Fn = void (*)(void *, std::shared_ptr<rcl_node_s>);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp11ServiceBaseC2ESt10shared_ptrI10rcl_node_sE"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    real(this_ptr, node_handle);

    mpk_exit_gate();
}

#include <dlfcn.h>
#include <cstdlib>

extern "C"
void
_ZN6rclcpp11ServiceBaseD2Ev_wrapper(void * this_ptr)
{
    using Fn = void (*)(void *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp11ServiceBaseD2Ev"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    real(this_ptr);

    mpk_exit_gate();
}

#include <dlfcn.h>
#include <cstdlib>

// Forward declarations only
struct rcl_node_s;

namespace rclcpp {
  class Logger;
}

extern "C"
void
_ZN6rclcpp15get_node_loggerEPK10rcl_node_s_wrapper(
    rclcpp::Logger * ret,
    const rcl_node_s * node)
{
    using Fn = void (*)(rclcpp::Logger *, const rcl_node_s *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp15get_node_loggerEPK10rcl_node_s"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    real(ret, node);

    mpk_exit_gate();
}

#include <dlfcn.h>
#include <cstdlib>



extern "C"
void
_ZN6rclcpp28expand_topic_or_service_nameERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES7_S7_b_wrapper(
    std::string * ret,
    const std::string * name,
    const std::string * node_name,
    const std::string * node_namespace,
    bool is_service)
{
    using Fn = void (*)(
        std::string *,
        const std::string *,
        const std::string *,
        const std::string *,
        bool);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp28expand_topic_or_service_nameERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES7_S7_b"
        );
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    real(ret, name, node_name, node_namespace, is_service);

    mpk_exit_gate();
}

#include <dlfcn.h>
#include <cstdlib>
#include <rcl/service.h>

extern "C"
rcl_service_t
rcl_get_zero_initialized_service_wrapper(void)
{
    using Fn = rcl_service_t (*)(void);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_get_zero_initialized_service");
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    rcl_service_t ret = real();

    mpk_exit_gate();
    return ret;
}

#include <dlfcn.h>
#include <cstdlib>
#include <rcl/service.h>
#include <rcl/service.h>
#include <rmw/types.h>

#include <dlfcn.h>
#include <cstdlib>

#include <rcl/service.h>
#include <rmw/types.h>

// extern "C"
// rcl_ret_t
// rcl_send_response_wrapper(
//     const rcl_service_t * service,
//     rmw_request_id_t * request_id,
//     void * ros_response)
// {
//     using Fn = rcl_ret_t (*)(
//         const rcl_service_t *,
//         rmw_request_id_t *,
//         void *);

//     static Fn real = nullptr;
//     if (!real) {
//         real = (Fn)dlsym(RTLD_NEXT, "rcl_send_response");
//         if (!real) {
//             abort();
//         }
//     }

//     mpk_entry_gate();

//     rcl_ret_t ret = real(service, request_id, ros_response);

//     mpk_exit_gate();
//     return ret;
// }


#include <dlfcn.h>
#include <cstdlib>

#include <rcl/service.h>
#include <rcl/node.h>

extern "C"
rcl_ret_t
rcl_service_fini_wrapper(
    rcl_service_t * service,
    rcl_node_t * node)
{
    using Fn = rcl_ret_t (*)(
        rcl_service_t *,
        rcl_node_t *);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_service_fini");
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    rcl_ret_t ret = real(service, node);

    mpk_exit_gate();
    return ret;
}


#include <dlfcn.h>
#include <cstdlib>

#include <rcl/service.h>

extern "C"
rcl_service_options_t
rcl_service_get_default_options_wrapper(void)
{
    using Fn = rcl_service_options_t (*)(void);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_service_get_default_options");
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    rcl_service_options_t ret = real();

    mpk_exit_gate();
    return ret;
}

extern "C"
rclcpp::Logger
_ZN6rclcpp10get_loggerERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE(
    const std::string & name)
{
    using Fn = rclcpp::Logger (*)(const std::string &);

    static Fn real = nullptr;
    if (!real) {
        real = (Fn)dlsym(
            RTLD_NEXT,
            "_ZN6rclcpp10get_loggerERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
        );
        if (!real) {
            abort();
        }
    }

    /* ---- your instrumentation ---- */
    mpk_entry_gate();   // or timestamp, logging, etc.
    /* -------------------------------- */

    rclcpp::Logger ret = real(name);

    /* ---- post instrumentation ---- */
    mpk_exit_gate();
    /* ------------------------------ */

    return ret;
}



#include <dlfcn.h>
#include <stdlib.h>
#include <rcl/client.h>

extern "C"
rcl_client_options_t
rcl_client_get_default_options_wrapper(void)
{
    using Fn = rcl_client_options_t (*)(void);

    static Fn real = NULL;
    if (!real) {
        real = (Fn)dlsym(RTLD_NEXT, "rcl_client_get_default_options");
        if (!real) {
            abort();
        }
    }

    mpk_entry_gate();

    rcl_client_options_t opts = real();

    mpk_exit_gate();

    return opts;
}
