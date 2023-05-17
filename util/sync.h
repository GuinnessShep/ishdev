#ifndef UTIL_SYNC_H
#define UTIL_SYNC_H
#define JUSTLOG 1

#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <setjmp.h>
#include <errno.h>
#include "misc.h"
#include "debug.h"
#include <strings.h>

// locks, implemented using pthread

#define LOCK_DEBUG 0

extern int current_pid(void);
extern int current_uid(void);
extern char* current_comm(void);
extern unsigned critical_region_count_wrapper(void);
extern void modify_critical_region_counter_wrapper(int, const char*, int);
extern unsigned locks_held_count_wrapper(void);
extern void modify_locks_held_count_wrapper(int);
extern struct pid *pid_get(dword_t id);
extern bool current_is_valid(void);
extern int safe_mutex_lock(pthread_mutex_t *mutex);
extern int safe_mutex_unlock(pthread_mutex_t *mutex);
extern void safe_strncpy(char *dest, const char *src, size_t dest_size);

extern bool doEnableExtraLocking;

extern struct timespec lock_pause;

typedef struct {
    pthread_mutex_t m;
    pthread_cond_t cond;
    pthread_rwlock_t l;
    // 0: unlocked
    // -1: write-locked
    // >0: read-locked with this many readers
    atomic_int val;
    pthread_rwlock_t read_pending_lock;
    atomic_int reads_pending; // Use atomic int for reads_pending
    const char *file;
    int line;
    int pid;
    char comm[16];
    char lname[16];
} wrlock_t;

void wrlock_init(wrlock_t *lock);
void write_lock(wrlock_t *lock, const char *file, int line);
void read_lock(wrlock_t *lock, const char *file, int line);
void read_unlock(wrlock_t *lock, const char *file, int line);
void read_to_write_lock(wrlock_t *lock);
void write_unlock(wrlock_t *lock, const char *file, int line);
void write_to_read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line);
void write_unlock_and_destroy(wrlock_t *lock);

typedef struct {
    pthread_mutex_t m;
    pthread_t owner;
    //const char *comm;
    int pid;
    int uid;
    char comm[16];
    char lname[16];  // The name of the lock.  -mke
    bool wait4; // Is this lock in use by wait4
#if LOCK_DEBUG
    struct lock_debug {
        const char *file; // doubles as locked
        int line;
        int pid;
        bool initialized;
    } debug;
#endif
} lock_t;

int lock_init(lock_t *lock, const char *lname);
void complex_lockt(lock_t *lock, int log_lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line);
void unlock_pids(lock_t *lock);
void unlock(lock_t *lock);
void simple_lockt(lock_t *lock, int log_lock);
int trylock(lock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line);
void write_lock_destroy(wrlock_t *lock);


#if LOCK_DEBUG
#define LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0, { .initialized = true }}
#else
#define LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0}
#endif

extern lock_t atomic_l_lock; // Used to make all lock operations atomic, even read->write and right->read -mke

pthread_mutexattr_t attr;
pthread_mutex_t atomic_l_lock_m;

void init_recursive_mutex(void) {
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&atomic_l_lock_m, &attr);
}

#define AL_DEBUG 1

inline void atomic_l_lockf(const char *lname, const char *file, int line) {
    if (!doEnableExtraLocking)
        return;
    if(AL_DEBUG) {
        printk("alock :(%s) %s:%d\n", lname, file, line);
    }

    int res = pthread_mutex_lock(&atomic_l_lock_m);
    if (res != 0) {
        // Handle error.
    } else {
        safe_strncpy((char *)&atomic_l_lock.comm, current_comm(), 16);
        safe_strncpy((char *)&atomic_l_lock.lname, lname, 16);
        modify_locks_held_count_wrapper(1);
    }

    modify_critical_region_counter_wrapper(1, file, line);
}

inline void atomic_l_unlockf(const char *lname, const char *file, int line) {
    if (!doEnableExtraLocking)
        return;
    
    if(AL_DEBUG) {
        printk("aUNlock :(%s)\n", atomic_l_lock.lname);
    }

    printk("aUNlock :(%s) %s:%d\n", lname, file, line);
    int res = pthread_mutex_unlock(&atomic_l_lock_m);
    if (res != 0) {
        // Handle error.
    }

    modify_locks_held_count_wrapper(-1);
    modify_critical_region_counter_wrapper(-1, "atomic_l_unlockf\0", 314);
}

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

extern __thread sigjmp_buf unwind_buf;
extern __thread bool should_unwind;

static inline int sigunwind_start(void) {
    if (sigsetjmp(unwind_buf, 1)) {
        should_unwind = false;
        return 1;
    } else {
        should_unwind = true;
        return 0;
    }
}

static inline void sigunwind_end(void) {
    should_unwind = false;
}

#endif
