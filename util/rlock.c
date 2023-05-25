#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <setjmp.h>
#include<errno.h>
#include "misc.h"
#include "debug.h"
#include "util/sync.h"
#include <strings.h>

// locks, implemented using pthread

#define LOCK_DEBUG 0

#include <errno.h>

int lock_init(lock_t *lock, const char *lname) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    if (pthread_mutex_init(&lock->m, &attr) != 0) {
        return errno;
    }

    if(lname != NULL) {
        strncpy(lock->lname, lname, 15);
        lock->lname[15] = '\0';
    } else {
        strncpy(lock->lname, "WTF", 15);
        lock->lname[15] = '\0';
    }

    lock->wait4 = false;

#if LOCK_DEBUG
    lock->debug = (struct lock_debug) {
        .initialized = true,
    };
#endif

    lock->comm[0] = 0;
    lock->uid = -1;
    lock->pid = -1;

    return 0;
}

#define MAX_COMM_LENGTH 16
#define INITIAL_BACKOFF 1000
#define MAX_BACKOFF 100000
#define MAX_ATTEMPTS 500

void complex_lockt(lock_t *lock, int log_lock, const char *file, int line) {
    unsigned int count = 0;
    unsigned int backoff = INITIAL_BACKOFF;
    const unsigned int max_backoff = MAX_BACKOFF;
    struct timespec lock_pause;
    
    while(pthread_mutex_trylock(&lock->m)) {
        if (count > MAX_ATTEMPTS) {
            if (!log_lock) {
                printk("ERROR: Possible deadlock(complex_lockt(%x), aborted lock attempt(PID: %d Process: %s) (Previously Owned:%s:%d) (Called By:%s:%d)\n", lock->m, current_pid(), current_comm(), lock->comm, lock->pid, file, line);
                pthread_mutex_unlock(&lock->m);
                modify_locks_held_count_wrapper(-1);
            }
            return;
        }
        
        lock_pause.tv_sec = 0;
        lock_pause.tv_nsec = backoff;
        nanosleep(&lock_pause, NULL);

        backoff = backoff * 2 > max_backoff ? max_backoff : backoff * 2;
        ++count;
    }
    
    modify_locks_held_count_wrapper(1);

    lock->owner = pthread_self();
    lock->pid = current_pid();
    lock->uid = current_uid();
    strncpy(lock->comm, current_comm(), MAX_COMM_LENGTH);
    lock->comm[MAX_COMM_LENGTH - 1] = '\0'; // ensure null termination

#if LOCK_DEBUG
    assert(lock->debug.initialized);
    assert(!lock->debug.file && "Attempting to recursively lock");
    lock->debug.file = file;
    lock->debug.line = line;
    lock->debug.pid = current_pid();
#endif
}


void simple_lockt(lock_t *lock, int log_lock) {
    pthread_mutex_lock(&lock->m);
    
    if (pthread_self() != lock->owner) {
        if(!log_lock) {
            critical_region_modify_wrapper(1,__FILE_NAME__, __LINE__);
            modify_locks_held_count_wrapper(1);
            lock->owner = pthread_self();
            lock->pid = current_pid();
            lock->uid = current_uid();
            strncpy(lock->comm, current_comm(), 16);
            critical_region_modify_wrapper(-1, __FILE_NAME__, __LINE__);
        } else {
            lock->owner = pthread_self();
            lock->pid = current_pid();
            lock->uid = current_uid();
            strncpy(lock->comm, current_comm(), 16);
        }
    }
        
    return;
}

void unlock(lock_t *lock) {
    
    if (pthread_self() == lock->owner) {
        lock->owner = zero_init(pthread_t);
        pthread_mutex_unlock(&lock->m);
        lock->pid = -1; //
        lock->comm[0] = 0;
        modify_locks_held_count_wrapper(-1);
    } else if(lock->pid > 0) {
        // It is an error, handle
        //printk("ERROR: Lock %d (%d:%s) attempted unlock by non locking owner (%d: %s)\n", lock, lock->pid, lock->comm, current_comm(), current_pid());
        printk("ERROR: Lock %d (%d:%s) attempted unlock by non locking owner\n", lock, lock->pid, lock->comm);
    }
    
    pthread_mutex_unlock(&lock->m);
    
#if LOCK_DEBUG
    assert(lock->debug.initialized);
    assert(lock->debug.file && "Attempting to unlock an unlocked lock");
    lock->debug = (struct lock_debug) { .initialized = true };
#endif
    return;
}

int trylock(lock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    int status = pthread_mutex_trylock(&lock->m);
#if LOCK_DEBUG
    if (!status) {
        lock->debug.file = file;
        lock->debug.line = line;
        extern int current_pid(void);
        lock->debug.pid = current_pid();
    }
#endif
    if((!status) && (current_pid() > 10)) {// iSH-AOK crashes if low number processes are not excluded.  Might be able to go lower then 10?  -mke
        if (pthread_self() != lock->owner) {
            modify_locks_held_count_wrapper(1);
            lock->pid = current_pid();
            strncpy(lock->comm, current_comm(), 16);
        }
    }
    return status;
}

#define trylock(lock) trylock(lock, __FILE_NAME__, __LINE__)
