#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include "misc.h"
#include "debug.h"
#include "util/sync.h"

#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

void wrlock_init(wrlock_t *lock) {
    pthread_mutex_init(&lock->m, NULL);
    pthread_cond_init(&lock->cond, NULL);
    pthread_rwlock_init(&lock->l, NULL);
    lock->val = 0;
    pthread_mutex_init(&lock->reads_pending.lock, NULL);
    lock->reads_pending.count = 0;
    pthread_mutex_init(&lock->writes_pending.lock, NULL);
    lock->writes_pending.count = 0;
    lock->write_recursion.owner = pthread_self();
    lock->write_recursion.count = 0;
    pthread_mutex_init(&lock->read_recursion.lock, NULL);
    lock->read_recursion.lock_infos = NULL;
    lock->read_recursion.lock_infos_count = 0;
    lock->file = NULL;
    lock->line = 0;
    lock->pid = 0;
    memset(lock->comm, 0, 16);
    memset(lock->lname, 0, 16);
}

void lock_writable(wrlock_t *lock, const char *file, int line) {
    pthread_mutex_lock(&lock->m);
    // Block until there are no readers or writers
    while (lock->val != 0) {
        pthread_cond_wait(&lock->cond, &lock->m);
    }
    // Indicate that a writer has acquired the lock
    lock->val = -1;
    lock->file = file;
    lock->line = line;
    lock->pid = getpid();
    pthread_mutex_unlock(&lock->m);
}

void lock_read_only(wrlock_t *lock, const char *file, int line) {
    pthread_mutex_lock(&lock->m);
    // Block until there are no writers
    while (lock->val == -1) {
        pthread_cond_wait(&lock->cond, &lock->m);
    }
    // Increment the count of readers
    lock->val += 1;
    lock->file = file;
    lock->line = line;
    lock->pid = getpid();
    pthread_mutex_unlock(&lock->m);
}

void unlock_read_only(wrlock_t *lock, const char *file, int line) {
    pthread_mutex_lock(&lock->m);
    if (lock->val > 0) {
        lock->val -= 1;
        pthread_cond_broadcast(&lock->cond);
    }
    lock->file = NULL;
    lock->line = 0;
    lock->pid = 0;
    pthread_mutex_unlock(&lock->m);
}

void lock_read_to_writable(wrlock_t *lock) {
    pthread_mutex_lock(&lock->m);
retry:
    while(lock->val != 1) {
        pthread_mutex_unlock(&lock->m);
        pthread_cond_wait(&lock->cond, &lock->m);
    }
    
    if(lock->val != 1) {
        goto retry;
    } else {
        lock->val = -1;
        pthread_mutex_unlock(&lock->m);
    }
}

void unlock_writable(wrlock_t *lock, const char *file, int line) {
    pthread_mutex_lock(&lock->m);
    if (lock->val == -1) {
        lock->val = 0;
        pthread_cond_broadcast(&lock->cond);
    }
    lock->file = NULL;
    lock->line = 0;
    lock->pid = 0;
    pthread_mutex_unlock(&lock->m);
}

void lock_write_to_read_only(wrlock_t *lock, __attribute__((unused)) const char *file, __attribute__((unused)) int line) {
    pthread_mutex_lock(&lock->m);
    if (lock->val == -1) {
        lock->val = 1;
    }
    lock->file = NULL;
    lock->line = 0;
    lock->pid = 0;
    pthread_mutex_unlock(&lock->m);
}

void write_unlock_and_destroy(wrlock_t *lock) {
    unlock_writable(lock, __FILE__, __LINE__);
    pthread_rwlock_destroy(&lock->l);
    pthread_cond_destroy(&lock->cond);
    pthread_mutex_destroy(&lock->m);
}
