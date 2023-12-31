#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "kernel/calls.h"
#include "kernel/task.h"
#include "kernel/resource_locking.h"
#include "emu/memory.h"
#include "emu/tlb.h"
#include "platform/platform.h"
#include "util/sync.h"
#include <libkern/OSAtomic.h>
#include <os/proc.h>

pthread_mutex_t multicore_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t extra_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t delay_lock = PTHREAD_MUTEX_INITIALIZER;
lock_t atomic_l_lock;
pthread_mutex_t wait_for_lock = PTHREAD_MUTEX_INITIALIZER;
time_t boot_time;  // Store the boot time.  -mke

bool BOOTING = true;

bool doEnableMulticore; // Enable multicore if toggled, should default to false
bool isGlibC = false; // Try to guess if we're running a non musl distro.  -mke
bool doEnableExtraLocking; // Enable extra locking if toggled, should default to true
unsigned doLockSleepNanoseconds; // How many nanoseconds should __lock() sleep between retries

__thread struct task *current;

static dword_t last_allocated_pid = 0;
static struct pid pids[MAX_PID + 1] = {};
lock_t pids_lock;
lock_t block_lock;
struct list alive_pids_list;

static bool pid_empty(struct pid *pid) {
    bool taskEmpty = pid->task == NULL;
    bool sessionEmpty = list_empty(&pid->session);
    bool pgroupEmpty = list_empty(&pid->pgroup);
    
    return taskEmpty && sessionEmpty && pgroupEmpty;
}

struct pid *pid_get(dword_t id) {
    if (id > sizeof(pids)/sizeof(pids[0]))
        return NULL;
    struct pid *pid = &pids[id];
    if (pid_empty(pid))
        return NULL;
    return pid;
}

struct task *pid_get_task_zombie(dword_t id) {
    struct pid *pid = pid_get(id);
    if (pid == NULL)
        return NULL;
    struct task *task = pid->task;
    return task;
}

struct task *pid_get_task(dword_t id) {
    struct task *task = pid_get_task_zombie(id);
    if (task != NULL && task->zombie)
        return NULL;
    return task;
}

struct pid *pid_get_last_allocated(void) {
    if (!last_allocated_pid) {
        return NULL;
    }
    return pid_get(last_allocated_pid);
}

dword_t get_count_of_blocked_tasks(void) {
    critical_region_modify(current, 1, __FILE_NAME__, __LINE__);
    dword_t res = 0;
    struct pid *pid_entry;
    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    list_for_each_entry(&alive_pids_list, pid_entry, alive) {
        if (pid_entry->task->io_block) {
            res++;
        }
    }
    critical_region_modify(current, -1, __FILE_NAME__, __LINE__);
    unlock(&pids_lock);
    return res;
}

void zero_critical_regions_count(void) { // If doEnableExtraLocking is changed to false, we need to zero out critical_region.count for active processes
    struct pid *pid_entry;
    list_for_each_entry(&alive_pids_list, pid_entry, alive) {
        pid_entry->task->critical_region.count = 0;  // Bad things happen if this isn't done.  -mke
    }
}

dword_t get_count_of_alive_tasks(void) {
    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    dword_t res = 0;
    struct list *item;
    list_for_each(&alive_pids_list, item) {
        res++;
    }
    unlock(&pids_lock);
    return res;
}

static struct pid *allocate_pid(void) {
    struct pid *pid = NULL;

    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);

    for (dword_t i = 1; i <= MAX_PID; ++i) {
        // Cycle through the pids array in a circular manner
        dword_t index = (last_allocated_pid + i) % MAX_PID;
        if (index == 0) index = 1;  // Avoid zero index

        if (pid_empty(&pids[index])) {
            last_allocated_pid = index;
            pid = &pids[last_allocated_pid];
            pid->id = last_allocated_pid;
            list_init(&pid->alive);
            list_init(&pid->session);
            list_init(&pid->pgroup);
            break;
        }
    }

    unlock(&pids_lock);

    if (pid == NULL) {
        // All PIDs are occupied. Handle this error in the caller.
    }

    return pid;
}

static void wait_for_task_exit_conditions(struct task *task) {
    bool signal_pending = !!(current->pending & ~current->blocked);
    int count = -4000;

    while (((critical_region_count(task) > 1) || (locks_held_count(task)) || (signal_pending)) && (count < 0)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->blocked);
        count++;
    }
}

void set_task_pid(struct task *task, int pid) {
    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    task->pid = pid;
    unlock(&pids_lock);
}

struct task *task_create_(struct task *parent) {
    struct pid *pid = allocate_pid();
    if (pid == NULL) {
        return NULL;
    }

    struct task *task = malloc(sizeof(struct task));
    if (task == NULL) {
        return NULL;
    }

    *task = (parent != NULL) ? *parent : (struct task) {};
    set_task_pid(task, pid->id);
    pid->task = task;
    list_add(&alive_pids_list, &pid->alive);

    list_init(&task->children);
    list_init(&task->siblings);
    if (parent != NULL) {
        task->parent = parent;
        list_add(&parent->children, &task->siblings);
    }

    task->pending = 0;
    list_init(&task->queue);
    task->clear_tid = 0;
    task->robust_list = 0;
    task->did_exec = false;
    lock_init(&task->general_lock, "task_creat_gen\0");

    task->sockrestart = (struct task_sockrestart) {};
    list_init(&task->sockrestart.listen);

    task->waiting_cond = NULL;
    task->waiting_lock = NULL;
    lock_init(&task->waiting_cond_lock, "task_creat_wait\0");
    cond_init(&task->pause);

    lock_init(&task->ptrace.lock, "task_creat_ptr\0");
    cond_init(&task->ptrace.cond);
    
    task->locks_held.count = 0;
    task->critical_region.count = 0;
    pthread_mutex_init(&task->critical_region.lock, NULL);
    pthread_mutex_init(&task->locks_held.lock, NULL);
    
    return task;
}

void task_destroy(struct task *task) {
    task->exiting = true;

    wait_for_task_exit_conditions(task);

    if (!trylock(&pids_lock, __FILE_NAME__, __LINE__)) {
        wait_for_task_exit_conditions(task);
        list_remove(&task->siblings);

        struct pid *pid = pid_get(task->pid);
        pid->task = NULL;

        wait_for_task_exit_conditions(task);
        list_remove(&pid->alive);

        wait_for_task_exit_conditions(task);
        unlock(&pids_lock);
    }

    free(task);
}


void run_at_boot(void) {  // Stuff we run only once, at boot time.
    //atomic_thread_fence(__ATOMIC_SEQ_CST);
    struct uname uts;
    do_uname(&uts);
    unsigned short ncpu = get_cpu_count();
    if(lock_init(&pids_lock, "pids\0") ||
       lock_init(&block_lock, "block\0")) {
        printk("ERROR: initializing internal locks at boot\n");
    }
       
    init_recursive_mutex(); // Initialize the atomic locking lock
    printk("iSH-AOK %s booted on %d emulated %s CPU(s)\n",uts.release, ncpu, uts.arch);

    // Get boot time
    extern time_t boot_time;
         
    boot_time = time(NULL);
    //printk("Seconds since January 1, 1970 = %ld\n", boot_time);
    BOOTING = false;

}

void task_run_current(void) {
    struct cpu_state *cpu = &current->cpu;
    struct tlb tlb = {};
    tlb_refresh(&tlb, &current->mem->mmu);
    
    while (true) {
        lock_read_only(&current->mem->lock, __FILE_NAME__, __LINE__);
        
        if(!doEnableMulticore) {
            safe_mutex_lock(&multicore_lock);
        }
        
        int interrupt = cpu_run_to_interrupt(cpu, &tlb);
        
        unlock_read_only(&current->mem->lock, __FILE_NAME__, __LINE__);
        
        if(!doEnableMulticore)
            pthread_mutex_unlock(&multicore_lock);
 
        //struct timespec while_pause = {0 /*secs*/, WAIT_SLEEP /*nanosecs*/};
        if(current->parent != NULL) {
            current->parent->group->group_count_in_int++; // Keep track of how many children the parent has
            handle_interrupt(interrupt);
            current->parent->group->group_count_in_int--;
        } else {
            handle_interrupt(interrupt);
        }
    }
}

static void *task_thread(void *task) {
    
    current = task;
    
    current->critical_region.count = 0; // Is this needed?  -mke
    
    update_thread_name();
    
    task_run_current();
    die("task_thread returned"); // above function call should never return
}

static pthread_attr_t task_thread_attr;
__attribute__((constructor)) static void create_attr(void) {
    pthread_attr_init(&task_thread_attr);
    pthread_attr_setdetachstate(&task_thread_attr, PTHREAD_CREATE_DETACHED);
}

void task_start(struct task *task) {
    if (pthread_create(&task->thread, &task_thread_attr, task_thread, task) < 0)
        die("could not create thread");
}

int_t sys_sched_yield(void) {
    STRACE("sched_yield()");
    sched_yield();
    return 0;
}

void update_thread_name(void) {
    char name[16]; // As long as Linux will let us make this
    snprintf(name, sizeof(name), "-%d", current->pid);
    size_t pid_width = strlen(name);
    size_t name_width = snprintf(name, sizeof(name), "%s", current->comm);
    sprintf(name + (name_width < sizeof(name) - 1 - pid_width ? name_width : sizeof(name) - 1 - pid_width), "-%d", current->pid);
#if __APPLE__
    pthread_setname_np(name);
#else
    pthread_setname_np(pthread_self(), name);
#endif
}
