#ifndef UTIL_SYNC_H
#define UTIL_SYNC_H
#define JUSTLOG 1

#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <setjmp.h>
#include<errno.h>
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

extern bool doEnableExtraLocking;

extern struct timespec lock_pause;

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

extern lock_t atomic_l_lock; // Used to make all lock operations atomic, even read->write and right->read -mke

// A safer string copy function that guarantees null-termination.
void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

// A helper function to lock a mutex and handle errors.
int safe_mutex_lock(pthread_mutex_t *mutex) {
    int res = pthread_mutex_lock(mutex);
    if (res != 0) {
        // Handle error as appropriate for your use case.
        printk("Error locking mutex: %d\n", res);
    }
    return res;
}

// A helper function to unlock a mutex and handle errors.
int safe_mutex_unlock(pthread_mutex_t *mutex) {
    int res = pthread_mutex_unlock(mutex);
    if (res != 0) {
        // Handle error as appropriate for your use case.
        printk("Error unlocking mutex: %d\n", res);
    }
    return res;
}

static inline void lock_init(lock_t *lock, char lname[16]) {
    pthread_mutex_init(&lock->m, NULL);
    if(lname != NULL) {
        strncpy(lock->lname, lname, 16);
    } else {
        strncpy(lock->lname, "WTF", 16);
    }
    lock->wait4 = false;
#if LOCK_DEBUG
    lock->debug = (struct lock_debug) {
        .initialized = true,
    };
#endif
    lock->comm[0] = 0;
    lock->uid = -1;
}

#if LOCK_DEBUG
#define LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0, { .initialized = true }}
#else
#define LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0}
#endif

static inline void atomic_l_lockf(wrlock_t *lock, char lname[16], const char *file, int line) {
    
    if(1) {
        int lval = atomic_load(&lock->val);
        printk("%s: %s %d (%d)(%d)\n", lname, file, line, lock, lval);
    }
    
    if (!doEnableExtraLocking)
        return;
    
    
    int res = 0;
    modify_critical_region_counter_wrapper(1, file, line);
    if (atomic_l_lock.pid > 0) {

        if (current_pid() != atomic_l_lock.pid) {
            res = safe_mutex_lock(&atomic_l_lock.m);
            if (res != 0) {
                // Handle error.
            } else {
                atomic_l_lock.pid = current_pid();
            }
        } else {
            printk("WARNING: Odd attempt by process (%s:%d) to attain same locking lock twice.  Ignoring\n", current_comm(), current_pid());
            res = 0;
        }
    }
    
    if (!res) {
        safe_strncpy((char *)&atomic_l_lock.comm, current_comm(), 16);
        safe_strncpy((char *)&atomic_l_lock.lname, lname, 16);
        modify_locks_held_count_wrapper(1);
    } else {
        printk("Error on locking lock (%s) Called from %s:%d\n", lname, file, line);
    }
    
    modify_critical_region_counter_wrapper(-1, file, line);
}

static inline void atomic_l_unlockf(void) {
    if (!doEnableExtraLocking)
        return;
    
    modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);
    safe_strncpy((char *)&atomic_l_lock.lname,"\0", 1);
    int res = safe_mutex_unlock(&atomic_l_lock.m);
    if (res != 0) {
        // Handle error.
    } else {
        atomic_l_lock.pid = -1;
    }
    
    modify_locks_held_count_wrapper(-1);
    modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
}

static inline void complex_lockt(lock_t *lock, int log_lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    // "Advanced" locking for some things.  pids_lock for instance
    //if(lock->pid == current_pid())
     //   return; //  Stupid?  Minimizes deadlocks, but... -mke
    unsigned int count = 0;
    int random_wait = WAIT_SLEEP + rand() % WAIT_SLEEP;
    struct timespec lock_pause = {0 /*secs*/, random_wait /*nanosecs*/};
    long count_max = (WAIT_MAX_UPPER - random_wait);  // As sleep time increases, decrease acceptable loops.  -mke
    
    while((pthread_mutex_trylock(&lock->m))) {
        count++;
        nanosleep(&lock_pause, NULL);
        if(count > count_max) {
            if(!log_lock) {
                printk("ERROR: Possible deadlock(complex_lockt(%x), aborted lock attempt(PID: %d Process: %s) (Previously Owned:%s:%d) (Called By:%s:%d)\n", lock->m, current_pid(), current_comm(), lock->comm, lock->pid, file, line);
                pthread_mutex_unlock(&lock->m);
                modify_locks_held_count_wrapper(-1);
            }
            return;
        }
        // Loop until lock works.  Maybe this will help make the multithreading work? -mke
    }
    
    modify_locks_held_count_wrapper(1);
    //modify_critical_region_counter_wrapper(-1,__FILE_NAME__, __LINE__);
    
    if(count > count_max * .90) {
        if(!log_lock)
           printk("Warning: large lock attempt count (%d)(complex_lockt(%x), aborted lock attempt(PID: %d Process: %s) (Previously Owned:%s:%d) (Called By:%s:%d)\n", count, lock->m, current_pid(), current_comm(), lock->comm, lock->pid, file, line);
    }

    lock->owner = pthread_self();
    lock->pid = current_pid();
    lock->uid = current_uid();
    strncpy(lock->comm, current_comm(), 16);
#if LOCK_DEBUG
    assert(lock->debug.initialized);
    assert(!lock->debug.file && "Attempting to recursively lock");
    lock->debug.file = file;
    lock->debug.line = line;
    extern int current_pid(void);
    lock->debug.pid = current_pid();
#endif
}

static inline void simple_lockt(lock_t *lock, int log_lock) {
    if(!log_lock) {
        modify_critical_region_counter_wrapper(1,__FILE_NAME__, __LINE__);
        pthread_mutex_lock(&lock->m);
        modify_locks_held_count_wrapper(1);
        lock->owner = pthread_self();
        lock->pid = current_pid();
        lock->uid = current_uid();
        strncpy(lock->comm, current_comm(), 16);
        modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
    } else {
        pthread_mutex_lock(&lock->m);
        lock->owner = pthread_self();
        lock->pid = current_pid();
        lock->uid = current_uid();
        strncpy(lock->comm, current_comm(), 16);
    }
    return;
}

static inline void unlock_pids(lock_t *lock) {
    lock->owner = zero_init(pthread_t);
    pthread_mutex_unlock(&lock->m);
    lock->pid = -1; //
    lock->comm[0] = 0;
    //modify_locks_held_count_wrapper(-1);
}

static inline void unlock(lock_t *lock) {
    //modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);
    
    lock->owner = zero_init(pthread_t);
    pthread_mutex_unlock(&lock->m);
    lock->pid = -1; //
    lock->comm[0] = 0;
    modify_locks_held_count_wrapper(-1);
    //modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
    
#if LOCK_DEBUG
    assert(lock->debug.initialized);
    assert(lock->debug.file && "Attempting to unlock an unlocked lock");
    lock->debug = (struct lock_debug) { .initialized = true };
#endif
    return;
}



static inline void _read_unlock(wrlock_t *lock, const char*, int);
static inline void _write_unlock(wrlock_t *lock, const char*, int);
static inline void write_unlock_and_destroy(wrlock_t *lock);

int lock_reads_pending_count(wrlock_t *lock, int increment) {
    pthread_rwlock_rdlock(&lock->read_pending_lock);
    if(increment)
        atomic_fetch_add(&lock->reads_pending, 1); // Use atomic increment
    int rpend = atomic_load(&lock->reads_pending); // Use atomic read
    pthread_rwlock_unlock(&lock->read_pending_lock); // Add unlock before returning
    return rpend;
}

int unlock_reads_pending_count(wrlock_t *lock) {
    pthread_rwlock_rdlock(&lock->read_pending_lock);
    atomic_fetch_sub(&lock->reads_pending, 1); // Use atomic decrement
    if(atomic_load(&lock->reads_pending) < 0)
        atomic_store(&lock->reads_pending, 0); // Use atomic store
    int rpend = atomic_load(&lock->reads_pending); // Use atomic read
    pthread_rwlock_unlock(&lock->read_pending_lock); // Add unlock before returning
    return rpend;
}

static inline void _read_unlock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    assert(lock->val > 0);
    atomic_fetch_sub(&lock->val, 1);
    if(lock->val < 0) {
        printk("ERROR: read_unlock(%x) error(PID: %d Process: %s count %d) (%s:%d)\n",lock, current_pid(), current_comm(), lock->val, file, line);
        //lock->val = 0;
        lock->pid = -1;
        lock->comm[0] = 0;
        modify_locks_held_count_wrapper(-1);
        pthread_rwlock_unlock(&lock->l);
        return;
    }
    pthread_rwlock_unlock(&lock->l);
    modify_locks_held_count_wrapper(-1);
}

static inline void read_unlock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    atomic_l_lockf(lock, "r_unlock\0", __FILE_NAME__, __LINE__);
    _read_unlock(lock, file, line);
    pthread_mutex_lock(&lock->m);
    pthread_cond_signal(&lock->cond);
    pthread_mutex_unlock(&lock->m);
    atomic_l_unlockf();
    
    return;
}

static inline void _write_unlock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    //modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);
    int lval = atomic_load(&lock->val);
    //assert(lval == -1);
    
    atomic_fetch_add(&lock->val, 1);

    lock->line = 0;
    lock->pid = -1;
    lock->comm[0] = 0;
    //STRACE("write_unlock(%x, %s(%d), %s, %d\n", lock, lock->comm, lock->pid, file, line);
    lock->file = NULL;
    modify_locks_held_count_wrapper(-1);
    //modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
    
    if(pthread_rwlock_unlock(&lock->l) != 0)
        printk("URGENT: write_unlock(%x:%d) error(PID: %d Process: %s) (%s:%d)\n", lock, lock->val, current_pid(), current_comm(), file, line);
    
    pthread_mutex_lock(&lock->m);
    pthread_cond_signal(&lock->cond);
    pthread_mutex_unlock(&lock->m);
}

static inline void write_unlock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) { // Wrap it.  External calls lock, internal calls using _write_unlock() don't -mke
    atomic_l_lockf(lock, "w_unlock\0", __FILE_NAME__, __LINE__);
    _write_unlock(lock, file, line);
    atomic_l_unlockf();
    return;
}

static inline void _write_lock(wrlock_t *lock, const char *file, int line) { // Write lock
    atomic_fetch_add(&lock->val, -1);
    
    lock->file = file;
    lock->line = line;
    lock->pid = current_pid();
    if(lock->pid > 9)
        strncpy((char *)lock->comm, current_comm(), 16);
    //STRACE("write_lock(%x, %s(%d), %s, %d\n", lock, lock->comm, lock->pid, file, line);
    //modify_critical_region_counter_wrapper(-1,__FILE_NAME__, __LINE__);
}

static inline void write_lock(wrlock_t *lock, const char *file, int line) {
    pthread_mutex_lock(&lock->m);
    while(atomic_load(&lock->val) > 0) { // If there are read locks, wait.
        pthread_cond_wait(&lock->cond, &lock->m);
    }
    atomic_l_lockf(lock, "w_lock", __FILE_NAME__, __LINE__);
    _write_lock(lock, file, line);
    atomic_l_unlockf();
    pthread_mutex_unlock(&lock->m);
}

static inline int trylockw(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    //modify_critical_region_counter_wrapper(1,__FILE_NAME__, __LINE__);
    atomic_l_lockf(lock, "trylockw\0", __FILE_NAME__, __LINE__);
    int status = pthread_rwlock_trywrlock(&lock->l);
#if LOCK_DEBUG
    if (!status) {
        lock->debug.file = file;
        lock->debug.line = line;
        extern int current_pid(void);
        lock->debug.pid = current_pid();
        atomic_fetch_add(&lock->val, 1);
        
    }
#endif
    if(!status) {
        modify_locks_held_count_wrapper(1);
        //STRACE("trylockw(%x, %s(%d), %s, %d\n", lock, lock->comm, lock->pid, file, line);
        
        lock->pid = current_pid();
        strncpy(lock->comm, current_comm(), 16);
        atomic_fetch_add(&lock->val, 1);
    }
    atomic_l_unlockf();
    return status;
}

#define trylockw(lock) trylockw(lock, __FILE_NAME__, __LINE__)

static inline int trylock(lock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    //modify_critical_region_counter_wrapper(1,__FILE_NAME__, __LINE__);
    atomic_l_lockf(lock, "trylock\0", __FILE_NAME__, __LINE__);
    int status = pthread_mutex_trylock(&lock->m);
    atomic_l_unlockf();
#if LOCK_DEBUG
    if (!status) {
        lock->debug.file = file;
        lock->debug.line = line;
        extern int current_pid(void);
        lock->debug.pid = current_pid();
    }
#endif
    if((!status) && (current_pid() > 10)) {// iSH-AOK crashes if low number processes are not excluded.  Might be able to go lower then 10?  -mke
        modify_locks_held_count_wrapper(1);
        
        //STRACE("trylock(%x, %s(%d), %s, %d\n", lock, lock->comm, lock->pid, file, line);
        lock->pid = current_pid();
        strncpy(lock->comm, current_comm(), 16);
    }
    return status;
}

#define trylock(lock) trylock(lock, __FILE_NAME__, __LINE__)

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

static inline void read_to_write_lock(wrlock_t *lock);
static inline void read_unlock_and_destroy(wrlock_t *lock);

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
    if (pthread_rwlock_init(&lock->l, pattr))
        printk("URGENT: wrlock_init() error(PID: %d Process: %s)\n",current_pid(), current_comm());
#else
    if (pthread_rwlock_init(&lock->l, pattr)) __builtin_trap();
#endif
    atomic_init(&lock->val, 0);
    lock->line = lock->pid = lock->reads_pending = 0;
    //strcpy(lock->comm,NULL);
    pthread_rwlock_init(&lock->read_pending_lock, NULL);
    lock->file = NULL;
}

static inline void _lock_destroy(wrlock_t *lock) {
    while((critical_region_count_wrapper() > 1) && (current_pid() != 1) && lock_reads_pending_count(lock, 0)) { // Wait for now, task is in one or more critical sections
        nanosleep(&lock_pause, NULL);
    }
#ifdef JUSTLOG
    if (pthread_rwlock_destroy(&lock->l) != 0) {
        printk("URGENT: lock_destroy(%x) on active lock. (PID: %d Process: %s Critical Region Count: %d)\n",&lock->l, current_pid(), current_comm(),critical_region_count_wrapper());
    }
#else
    if (pthread_rwlock_destroy(&lock->l) != 0) __builtin_trap();
#endif
}

static inline void lock_destroy(wrlock_t *lock) {
    while((critical_region_count_wrapper() > 1) && (current_pid() != 1)) { // Wait for now, task is in one or more critical sections
        nanosleep(&lock_pause, NULL);
    }
    
    atomic_l_lockf(lock, "l_destroy\0", __FILE_NAME__, __LINE__);
    _lock_destroy(lock);
    atomic_l_unlockf();
}

static inline void _read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    //lock_reads_pending_count(lock, 1);
    atomic_fetch_add(&lock->reads_pending, 1);
    pthread_rwlock_rdlock(&lock->l);
    atomic_fetch_sub(&lock->reads_pending, 1);
    atomic_fetch_add(&lock->val, 1);
    //unlock_reads_pending_count(lock);
    
    lock->pid = current_pid();
    if(lock->pid > 9)
        strncpy((char *)lock->comm, current_comm(), 16);
    
    return;
    
}

static inline void read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) { // Wrapper so that external calls lock, internal calls using _read_unlock() don't -mke
    atomic_l_lockf(lock, "r_lock\0", __FILE_NAME__, __LINE__);
    _read_lock(lock, file, line);
    atomic_l_unlockf();
}

static inline void read_to_write_lock(wrlock_t *lock) {  // Try to atomically swap a RO lock to a Write lock.  -mke
    modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);
    atomic_l_lockf(lock, "rtw_lock\0", __FILE_NAME__, __LINE__);
    _read_unlock(lock, __FILE_NAME__, __LINE__);
    _write_lock(lock, __FILE_NAME__, __LINE__);
    atomic_l_unlockf();
    modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
}

static inline void write_to_read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) { // Try to atomically swap a Write lock to a RO lock.  -mke
    modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);
    atomic_l_lockf(lock, "wtr_lock\0", __FILE_NAME__, __LINE__);
    _write_unlock(lock, file, line);
    _read_lock(lock, file, line);
    atomic_l_unlockf();
    modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
}

static inline void write_unlock_and_destroy(wrlock_t *lock) {
    modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);

    atomic_l_lockf(lock, "wuad_lock\0", __FILE_NAME__, __LINE__);
    _write_unlock(lock, __FILE_NAME__, __LINE__);
    _lock_destroy(lock);
    atomic_l_unlockf();
    modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
}

static inline void read_unlock_and_destroy(wrlock_t *lock) {
    //modify_critical_region_counter_wrapper(1, __FILE_NAME__, __LINE__);
    atomic_l_lockf(lock, "ruad_lock", __FILE_NAME__, __LINE__);
    if(trylockw(lock)) // It should be locked, but just in case.  Likely masking underlying issue.  -mke
        _read_unlock(lock, __FILE_NAME__, __LINE__);
    _lock_destroy(lock);
    atomic_l_unlockf();
    //modify_critical_region_counter_wrapper(-1, __FILE_NAME__, __LINE__);
}

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
