#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include "misc.h"
#include "debug.h"
#include "util/sync.h"

// R/W locks, implemented using pthread

#define LOCK_DEBUG 0

void safe_strncpy(char *dest, const char *src, size_t dest_size);

// A safer string copy function that guarantees null-termination.
void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

int safe_mutex_lock(pthread_mutex_t *mutex) {
    int res = pthread_mutex_lock(mutex);
    if (res != 0) {
        printk("ERROR: locking mutex: %d\n", res);
        exit(EXIT_FAILURE); // Exit on failure
    }
    return res;
}

int safe_mutex_unlock(pthread_mutex_t *mutex) {
    int res = pthread_mutex_unlock(mutex);
    if (res != 0) {
        printk("ERROR: unlocking mutex: %d\n", res);
        exit(EXIT_FAILURE); // Exit on failure
    }
    return res;
}

static inline void _read_unlock(wrlock_t *lock, const char*, int);
static inline void _write_unlock(wrlock_t *lock, const char*, int);
void write_unlock_and_destroy(wrlock_t *lock);

void increment_reads_pending_count(wrlock_t *lock) {
    safe_mutex_lock(&lock->reads_pending.lock);
    atomic_fetch_add(&lock->reads_pending.count, 1);
    safe_mutex_unlock(&lock->reads_pending.lock);
}

int get_reads_pending_count(wrlock_t *lock) {
    safe_mutex_lock(&lock->reads_pending.lock);
    int rpend = atomic_load(&lock->reads_pending.count);
    safe_mutex_unlock(&lock->reads_pending.lock);
    return rpend;
}

void decrement_reads_pending_count(wrlock_t *lock) {
    safe_mutex_lock(&lock->reads_pending.lock);
    atomic_fetch_sub(&lock->reads_pending.count, 1);
    safe_mutex_unlock(&lock->reads_pending.lock);
}

void _write_unlock(wrlock_t *lock, const char *file, int line) {
    if (lock->recursion.owner != pthread_self()) { // if the thread doesn't own the lock
        printk("ERROR: Non owner thread/process trying to unlock internal write lock(%d)", lock);
        return;
    }
    if (--lock->recursion.count > 0) { // if the lock was recursively acquired
        return;
    }
    atomic_fetch_add(&lock->val, 1);
    lock->line = 0;
    lock->pid = -1;
    lock->recursion.owner = NULL; // reset the owner of the lock
    lock->comm[0] = 0;
    lock->file = NULL;
    modify_locks_held_count_wrapper(-1);
    if(pthread_rwlock_unlock(&lock->l) != 0)
        printk("URGENT: write_unlock(%x:%d) error(PID: %d Process: %s) (%s:%d)\n", lock, atomic_load(&lock->val), current_pid(), current_comm(), file, line);
}

void write_unlock(wrlock_t *lock, const char *file, int line) {
    atomic_l_lockf(lock, "w_unlock\0", __FILE_NAME__, __LINE__);
    _write_unlock(lock, file, line);
    atomic_l_unlockf(lock, "w_unlock\0", __FILE_NAME__, __LINE__);
}

void _write_lock(wrlock_t *lock, const char *file, int line) {
    if (lock->recursion.owner == pthread_self()) { // if the thread already owns the lock
        lock->recursion.count++;
        return;
    }
    atomic_fetch_add(&lock->val, -1);
    lock->file = file;
    lock->line = line;
    lock->pid = current_pid();
    lock->recursion.owner = pthread_self(); // set the current thread as the owner of the lock
    lock->recursion.count = 1; // initialize lock count
    if (lock->pid > 9) {
        strncpy(lock->comm, current_comm(), 15);
        lock->comm[15] = '\0'; // Ensure null termination
    }
}

void write_lock(wrlock_t *lock, const char *file, int line) {
    pthread_mutex_lock(&lock->m);
    while (atomic_load(&lock->val) > 0) {
        pthread_mutex_unlock(&lock->m); // Release the lock to let other threads modify lock->val
        pthread_cond_wait(&lock->cond, &lock->m); // Wait for the condition (lock->val to become 0)
        pthread_mutex_lock(&lock->m); // Reacquire the lock
    }

    atomic_l_lockf(lock, "w_lock", __FILE_NAME__, __LINE__);
    _write_lock(lock, file, line);
    atomic_l_unlockf(lock, "w_lock", __FILE_NAME__, __LINE__);

    pthread_mutex_unlock(&lock->m);
}

int trylockw(wrlock_t *lock, const char *file, int line) {
    atomic_l_lockf(lock, "trylockw\0", __FILE_NAME__, __LINE__);
    int status = pthread_rwlock_trywrlock(&lock->l);

#if LOCK_DEBUG
    if (!status) {
        lock->file = file;
        lock->line = line;
        lock->pid = current_pid();
        atomic_fetch_add(&lock->val, 1);
    }
#endif

    if(!status) {
        modify_locks_held_count_wrapper(1);
        lock->pid = current_pid();
        strncpy(lock->comm, current_comm(), 15);
        lock->comm[15] = '\0'; // Ensure null termination
        atomic_fetch_add(&lock->val, 1);
    }
    atomic_l_unlockf(lock, "trylockw\0", __FILE_NAME__, __LINE__);
    return status;
}

#define trylockw(lock) trylockw(lock, __FILE_NAME__, __LINE__)

void read_to_write_lock(wrlock_t *lock);
static inline void read_unlock_and_destroy(wrlock_t *lock);

// this is a read-write lock that prefers writers, i.e. if there are any
// writers waiting a read lock will block.
// on darwin pthread_rwlock_t is already like this, on linux you can configure
// it to prefer writers. not worrying about anything else right now.

void wrlock_init(wrlock_t *lock) {
    pthread_rwlockattr_t *pattr = NULL;
#if defined(__GLIBC__)
    pthread_rwlockattr_t attr;
    pattr = &attr;
    pthread_rwlockattr_init(pattr);
    pthread_rwlockattr_setkind_np(pattr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
#ifdef JUSTLOG
    if (pthread_rwlock_init(&lock->l, pattr))
        printk("URGENT: wrlock_init() 'l' error(PID: %d Process: %s)\n",current_pid(), current_comm());
    if (pthread_mutex_init(&lock->m, NULL))
        printk("URGENT: wrlock_init() 'm' error(PID: %d Process: %s)\n",current_pid(), current_comm());
    if (pthread_mutex_init(&lock->reads_pending.lock, NULL))
        printk("URGENT: wrlock_init() 'reads_pending_lock error(PID: %d Process: %s)\n",current_pid(), current_comm());
    atomic_init(&lock->reads_pending.count, 0);
#else
    if (pthread_rwlock_init(&lock->l, pattr)) __builtin_trap();
#endif
    atomic_init(&lock->val, 0);
    lock->line = lock->pid = lock->recursion.count = 0;
    lock->recursion.owner = NULL;
    lock->file = NULL;
}

static inline void _write_lock_destroy(wrlock_t *lock) {
    while((critical_region_count_wrapper() > 1) && (current_pid() != 1) && get_reads_pending_count(lock)) { // Wait for now, task is in one or more critical sections
        nanosleep(&lock_pause, NULL);
    }
#ifdef JUSTLOG
    if (pthread_rwlock_destroy(&lock->l) != 0) {
        printk("URGENT: write_lock_destroy(%x) on active lock. (PID: %d Process: %s Critical Region Count: %d)\n",&lock->l, current_pid(), current_comm(),critical_region_count_wrapper());
    }
#else
    if (pthread_rwlock_destroy(&lock->l) != 0) __builtin_trap();
#endif
}

void write_lock_destroy(wrlock_t *lock) {
    while((critical_region_count_wrapper() > 1) && (current_pid() != 1)) { // Wait for now, task is in one or more critical sections
        nanosleep(&lock_pause, NULL);
    }
    
    atomic_l_lockf(lock, "l_destroy\0", __FILE_NAME__, __LINE__);
    _write_lock_destroy(lock);
    atomic_l_unlockf(lock, "l_destroy\0", __FILE_NAME__, __LINE__);
}

static inline void _read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    increment_reads_pending_count(lock);
    pthread_rwlock_rdlock(&lock->l);
    atomic_fetch_add(&lock->val, 1);
    
    lock->pid = current_pid();
    
    if(lock->pid > 9)
        strncpy((char *)lock->comm, current_comm(), 16);
    
    return;
    
}

void read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) { // Wrapper so that external calls lock, internal calls using _read_unlock() don't -mke
    atomic_l_lockf(lock, "r_lock\0", __FILE_NAME__, __LINE__);
    _read_lock(lock, file, line);
    atomic_l_unlockf(lock, "r_lock\0", __FILE_NAME__, __LINE__);
}

static inline void _read_unlock(wrlock_t *lock, const char *file, int line) {
    //assert(atomic_load(&lock->val) > 0); // This should in theory be safe since the atomic_l_lockf() function has been invoked prior.
    atomic_fetch_sub(&lock->val, 1);
    decrement_reads_pending_count(lock);
    if(atomic_load(&lock->val) < 0) {
        printk("ERROR: read_unlock(%x) error(PID: %d Process: %s count %d) (%s:%d)\n",lock, current_pid(), current_comm(), atomic_load(&lock->val), file, line);
        lock->pid = -1;
        lock->comm[0] = 0;
        modify_locks_held_count_wrapper(-1);
        pthread_rwlock_unlock(&lock->l);
        return;
    }
    pthread_rwlock_unlock(&lock->l);
    modify_locks_held_count_wrapper(-1);
}

void read_unlock(wrlock_t *lock, const char *file, int line) {
    atomic_l_lockf(lock, "r_unlock\0", __FILE_NAME__, __LINE__);
    _read_unlock(lock, file, line);
    pthread_mutex_lock(&lock->m);
    pthread_cond_signal(&lock->cond);
    pthread_mutex_unlock(&lock->m);
    atomic_l_unlockf(lock, "r_unlock\0", __FILE_NAME__, __LINE__);
}


void read_to_write_lock(wrlock_t *lock) {  // Try to atomically swap a RO lock to a Write lock.  -mke
    critical_region_modify_wrapper(1, __FILE_NAME__, __LINE__);
    atomic_l_lockf(lock, "rtw_lock\0", __FILE_NAME__, __LINE__);
    _read_unlock(lock, __FILE_NAME__, __LINE__);
    _write_lock(lock, __FILE_NAME__, __LINE__);
    atomic_l_unlockf(lock, "rtw_lock\0", __FILE_NAME__, __LINE__);
    critical_region_modify_wrapper(-1, __FILE_NAME__, __LINE__);
}

void write_to_read_lock(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) { // Try to atomically swap a Write lock to a RO lock.  -mke
    critical_region_modify_wrapper(1, __FILE_NAME__, __LINE__);
    
    atomic_l_lockf(lock, "wtr_lock\0", __FILE_NAME__, __LINE__);
    _write_unlock(lock, file, line);
    _read_lock(lock, file, line);
    atomic_l_unlockf(lock, "wtr_lock\0", __FILE_NAME__, __LINE__);
    
    critical_region_modify_wrapper(-1, __FILE_NAME__, __LINE__);
}

void write_unlock_and_destroy(wrlock_t *lock) {
    critical_region_modify_wrapper(1, __FILE_NAME__, __LINE__);
    
    atomic_l_lockf(lock, "wuad_lock\0", __FILE_NAME__, __LINE__);
    _write_unlock(lock, __FILE_NAME__, __LINE__);
    _write_lock_destroy(lock);
    atomic_l_unlockf(lock, "wuad_lock\0", __FILE_NAME__, __LINE__);
    
    critical_region_modify_wrapper(-1, __FILE_NAME__, __LINE__);
}

void read_unlock_and_destroy(wrlock_t *lock) {
    atomic_l_lockf(lock, "ruad_lock", __FILE_NAME__, __LINE__);
   // if(trylockw(lock)) // It should be locked, but just in case.  Likely masking underlying issue.  -mke
    //    _read_unlock(lock, __FILE_NAME__, __LINE__);
    _write_lock_destroy(lock);
    atomic_l_unlockf(lock, "ruad_lock", __FILE_NAME__, __LINE__);
}
