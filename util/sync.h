#ifndef UTIL_SYNC_H
#define UTIL_SYNC_H
#define JUSTLOG 1

#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <setjmp.h>
#include "misc.h"
#include "debug.h"

// locks, implemented using pthread

#define LOCK_DEBUG 0

extern int current_pid(void);
extern char* current_comm(void);

extern struct timespec lock_pause;

typedef struct {
    pthread_mutex_t m;
    pthread_t owner;
#if LOCK_DEBUG
    struct lock_debug {
        const char *file; // doubles as locked
        int line;
        int pid;
        bool initialized;
    } debug;
#endif
} lock_t;

static inline void lock_init(lock_t *lock) {
    pthread_mutex_init(&lock->m, NULL);
#if LOCK_DEBUG
    lock->debug = (struct lock_debug) {
        .initialized = true,
    };
#endif
}

#if LOCK_DEBUG
#define LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0, { .initialized = true }}
#else
#define LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0}
#endif

static inline void __lock(lock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    unsigned int count = 0;
    long count_max = (255000 - lock_pause.tv_nsec);  // As sleep time increases, decrease acceptable loops.  -mke
    while(pthread_mutex_trylock(&lock->m)) {
        count++;
        nanosleep(&lock_pause, NULL);
        if(count > count_max * .90) {
            printk("ERROR: Possible deadlock, aborted lock attempt(PID: %d Process: %s) from file %s\n",current_pid(), current_comm(), file);
            return;
        }
        // Loop until lock works.  Maybe this will help make the multithreading work? -mke
    }

    if(count > count_max * .90) {
        printk("WARNING: large lock attempt count(__lock(%d)) from file %s\n",count, file);
    }

    lock->owner = pthread_self();
#if LOCK_DEBUG
    assert(lock->debug.initialized);
    assert(!lock->debug.file && "Attempting to recursively lock");
    lock->debug.file = file;
    lock->debug.line = line;
    extern int current_pid(void);
    lock->debug.pid = current_pid();
#endif
}

#define lock(lock) __lock(lock, __FILE__, __LINE__)

static inline void unlock(lock_t *lock) {
#if LOCK_DEBUG
    assert(lock->debug.initialized);
    assert(lock->debug.file && "Attempting to unlock an unlocked lock");
    lock->debug = (struct lock_debug) { .initialized = true };
#endif
    lock->owner = zero_init(pthread_t);
    pthread_mutex_unlock(&lock->m);
}

typedef struct {
    pthread_rwlock_t l;
    // 0: unlocked
    // -1: write-locked
    // >0: read-locked with this many readers
    atomic_int val;
    const char *file;
    int line;
    int pid;
} wrlock_t;

static inline int trylockw(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    int status = pthread_rwlock_trywrlock(&lock->l);
#if LOCK_DEBUG
    if (!status) {
        lock->debug.file = file;
        lock->debug.line = line;
        extern int current_pid(void);
        lock->debug.pid = current_pid();
    }
#endif
    return status;
}

#define trylockw(lock) trylockw(lock, __FILE__, __LINE__)

static inline int trylock(lock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    int status = pthread_mutex_trylock(&lock->m);
#if LOCK_DEBUG
    if (!status) {
        lock->debug.file = file;
        lock->debug.line = line;
        extern int current_pid(void);
        lock->debug.pid = current_pid();
    }
#endif
    return status;
}

#define trylock(lock) trylock(lock, __FILE__, __LINE__)

// conditions, implemented using pthread conditions but hacked so you can also
// be woken by a signal

typedef struct {
    pthread_cond_t cond;
} cond_t;
#define COND_INITIALIZER ((cond_t) {PTHREAD_COND_INITIALIZER})

// Must call before using the condition
void cond_init(cond_t *cond);
// Must call when finished with the condition (currently doesn't do much but might do something important eventually I guess)
void cond_destroy(cond_t *cond);
// Releases the lock, waits for the condition, and reacquires the lock.
// Returns _EINTR if waiting stopped because the thread received a signal,
// _ETIMEDOUT if waiting stopped because the timout expired, 0 otherwise.
// Will never return _ETIMEDOUT if timeout is NULL.
int must_check wait_for(cond_t *cond, lock_t *lock, struct timespec *timeout);
// Same as wait_for, except it will never return _EINTR
int wait_for_ignore_signals(cond_t *cond, lock_t *lock, struct timespec *timeout);
// Wake up all waiters.
void notify(cond_t *cond);
// Wake up one waiter.
void notify_once(cond_t *cond);

// this is a read-write lock that prefers writers, i.e. if there are any
// writers waiting a read lock will block.
// on darwin pthread_rwlock_t is already like this, on linux you can configure
// it to prefer writers. not worrying about anything else right now.

static inline void wrlock_init(wrlock_t *lock) {
    pthread_rwlockattr_t *pattr = NULL;
#if defined(__GLIBC__)
    pthread_rwlockattr_t attr;
    pattr = &attr;
    pthread_rwlockattr_init(pattr);
    pthread_rwlockattr_setkind_np(pattr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
#ifdef JUSTLOG
    if (pthread_rwlock_init(&lock->l, pattr)) printk("URGENT: wrlock_init() error(PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_init(&lock->l, pattr)) __builtin_trap();
#endif
    lock->val = lock->line = lock->pid = 0;
    lock->file = NULL;
}

static inline void wrlock_destroy(wrlock_t *lock) {
#ifdef JUSTLOG
    if (pthread_rwlock_destroy(&lock->l) != 0) printk("URGENT: wlock_destroy() error(PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_destroy(&lock->l) != 0) __builtin_trap();
#endif
}

static inline void read_lock(wrlock_t *lock) {
#ifdef JUSTLOG
    if (pthread_rwlock_rdlock(&lock->l) != 0) printk("URGENT: read_lock() error (PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_rdlock(&lock->l) != 0) __builtin_trap();
#endif
    assert(lock->val >= 0);
    lock->val++;
}

static inline void read_unlock(wrlock_t *lock) {
    if(lock->val <=0) {
        printk("URGENT: pthread_rwlock_unlock error(PID: %d Process: %s count %d) \n",current_pid(), current_comm(), lock->val);
	return;
    }
    assert(lock->val > 0);
    lock->val--;
#ifdef JUSTLOG
    if (pthread_rwlock_unlock(&lock->l) != 0) printk("URGENT: read_unlock() error(PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_unlock(&lock->l) != 0) __builtin_trap();
#endif
}

static inline void __write_lock(wrlock_t *lock, const char *file, int line) {
#ifdef JUSTLOG
    if (pthread_rwlock_wrlock(&lock->l) != 0) printk("URGENT: __write_wrilock() error(PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_wrlock(&lock->l) != 0) __builtin_trap();
#endif
    assert(lock->val == 0);
    lock->val = -1;
    lock->file = file;
    lock->line = line;
    lock->pid = current_pid();
}

#define write_lock(lock) __write_lock(lock, __FILE__, __LINE__)

static inline void write_unlock(wrlock_t *lock) {
    assert(lock->val == -1);
    lock->val = lock->line = lock->pid = 0;
    lock->file = NULL;
#ifdef JUSTLOG
    if (pthread_rwlock_unlock(&lock->l) != 0) printk("URGENT: write_lock() error(PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_unlock(&lock->l) != 0) __builtin_trap();
#endif
}

extern __thread sigjmp_buf unwind_buf;
extern __thread bool should_unwind;
static inline int sigunwind_start() {
    if (sigsetjmp(unwind_buf, 1)) {
        should_unwind = false;
        return 1;
    } else {
        should_unwind = true;
        return 0;
    }
}

static inline void sigunwind_end() {
    should_unwind = false;
}

#endif
