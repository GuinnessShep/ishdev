#include <string.h>
#include "kernel/calls.h"
#include "kernel/resource_locking.h"

extern bool doEnableExtraLocking;
extern pthread_mutex_t extra_lock;

#define ERROR_CONDITION -1
#define ZERO_ADDRESS 0

static int __user_read_task(struct task *task, addr_t addr, void *buf, size_t count) {
    char *cbuf = (char *) buf;
    addr_t p = addr;
    while (p < addr + count) {
        addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        if (chunk_end > addr + count)
            chunk_end = addr + count;
        const char *ptr = mem_ptr(task->mem, p, MEM_READ);
        if (ptr == NULL) {
            return 1;
	}
        memcpy(&cbuf[p - addr], ptr, chunk_end - p);
        p = chunk_end;
    }
    return 0;
}

static int __user_write_task(struct task *task, addr_t addr, const void *buf, size_t count, bool ptrace) {
    const char *cbuf = (const char *) buf;
    addr_t p = addr;
    while (p < addr + count) {
        addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        if (chunk_end > addr + count)
            chunk_end = addr + (addr_t)count;
        char *ptr = mem_ptr(task->mem, p, ptrace ? MEM_WRITE_PTRACE : MEM_WRITE);
        if (ptr == NULL)
            return 1;
        memcpy(ptr, &cbuf[p - addr], chunk_end - p);
        
        p = chunk_end;
    }
    return 0;
}

int user_read_task(struct task *task, addr_t addr, void *buf, size_t count) {
    read_lock(&task->mem->lock, __FILE_NAME__, __LINE__);

    int res = __user_read_task(task, addr, buf, count);

    read_unlock(&task->mem->lock, __FILE_NAME__, __LINE__);
    return res;
}

int user_read(addr_t addr, void *buf, size_t count) {
    return user_read_task(current, addr, buf, count);
}

int user_write_task(struct task *task, addr_t addr, const void *buf, size_t count) {
    read_lock(&task->mem->lock, __FILE_NAME__, __LINE__);
    int res = __user_write_task(task, addr, buf, count, false);
    read_unlock(&task->mem->lock, __FILE_NAME__, __LINE__);
    return res;
}

int user_write_task_ptrace(struct task *task, addr_t addr, const void *buf, size_t count) {
    read_lock(&task->mem->lock, __FILE_NAME__, __LINE__);
    int res = __user_write_task(task, addr, buf, count, true);
    read_unlock(&task->mem->lock, __FILE_NAME__, __LINE__);
    return res;
}

int user_write(addr_t addr, const void *buf, size_t count) {
    return user_write_task(current, addr, buf, count);
}

int user_read_string(addr_t addr, char *buf, size_t max) {
    if (addr == ZERO_ADDRESS) {
        return ERROR_CONDITION;
    }

    read_lock(&current->mem->lock, __FILE_NAME__, __LINE__);

    size_t i = 0;
    while (i < max) {
        if (__user_read_task(current, addr + i, &buf[i], 1)) {
            read_unlock(&current->mem->lock, __FILE_NAME__, __LINE__);
            return ERROR_CONDITION;
        }
        if (buf[i] == '\0')
            break;
        i++;
    }

    read_unlock(&current->mem->lock, __FILE_NAME__, __LINE__);
    return 0;
}

int user_write_string(addr_t addr, const char *buf) {
    if (addr == ZERO_ADDRESS) {
        return ERROR_CONDITION;
    }

    read_lock(&current->mem->lock, __FILE_NAME__, __LINE__);

    size_t i = 0;
    do {
        if (__user_write_task(current, addr + i, &buf[i], 1, false)) {
            read_unlock(&current->mem->lock, __FILE_NAME__, __LINE__);
            return ERROR_CONDITION;
        }
        i++;
    } while (buf[i - 1] != '\0');

    read_unlock(&current->mem->lock, __FILE_NAME__, __LINE__);
    return 0;
}
