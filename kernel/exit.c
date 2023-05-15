#include <pthread.h>
#include <signal.h>
#include <string.h>
#include "kernel/calls.h"
#include "kernel/mm.h"
#include "kernel/futex.h"
#include "kernel/ptrace.h"
#include "kernel/resource_locking.h"
#include "fs/fd.h"
#include "fs/tty.h"

extern bool doEnableExtraLocking;
extern pthread_mutex_t extra_lock;
extern dword_t extra_lock_pid;
extern const char extra_lock_comm;

static void halt_system(void);

static bool exit_tgroup(struct task *task) {
    while((critical_region_count(task) > 2) || (locks_held_count(task))) { // Wait for now, task is in one or more critical sections, and/or has locks
        nanosleep(&lock_pause, NULL);
    }
    struct tgroup *group = task->group;
    list_remove(&task->group_links);
    bool group_dead = list_empty(&group->threads);
    if (group_dead) {
        // don't need to lock the group since the only pointers to it come from:
        // - other threads' current->group, but there are none left thanks to that list_empty call
        // - locking pids_lock first, which do_exit did
        if (group->itimer)
            timer_free(group->itimer);

        // The group will be removed from its group and session by reap_if_zombie,
        // because fish tries to set the pgid to that of an exited but not reaped
        // task.
        // https://github.com/Microsoft/WSL/issues/2786
    }
    return group_dead;
}

void (*exit_hook)(struct task *task, int code) = NULL;

static struct task *find_new_parent(struct task *task) {
    struct task *new_parent;
    list_for_each_entry(&task->group->threads, new_parent, group_links) {
        if (!new_parent->exiting)
            return new_parent;
    }
    return pid_get_task(1);
}

noreturn void do_exit(int status) {
    //atomic_l_lockf(0,__FILE_NAME__, __LINE__);
       
    current->exiting = true;
    
    bool signal_pending = !!(current->pending & ~current->blocked);
    // has to happen before mm_release
    
    while((critical_region_count(current) > 1) ||
          (locks_held_count(current)) ||
          (current->process_info_being_read) ||
          (signal_pending)) { // Wait for now, task is in one or more critical sections, and/or has locks, or signals in flight
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    }
    addr_t clear_tid = current->clear_tid;
    if (clear_tid) {
        pid_t_ zero = 0;
        if (user_put(clear_tid, zero) == 0)
            futex_wake(clear_tid, 1);
    }

    // release all our resources
    do {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    } while((critical_region_count(current) > 1) ||
            (locks_held_count(current)) ||
            (current->process_info_being_read) ||
            (signal_pending)); // Wait for now, task is in one or more critical
    mm_release(current->mm);
    current->mm = NULL;
    
    signal_pending = !!(current->pending & ~current->blocked);
    while((critical_region_count(current) > 1) ||
          (locks_held_count(current)) ||
          (current->process_info_being_read) ||
          (signal_pending)) { // Wait for now, task is in one or more critical // Wait for now, task is in one or more critical sections, and/or has locks, or signals in flight
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    }
    fdtable_release(current->files);
    current->files = NULL;
    
    while((critical_region_count(current) > 1) ||
          (locks_held_count(current)) ||
          (current->process_info_being_read) ||
          (signal_pending)) { // Wait for now, task is in one or more critical // Wait for now, task is in one or more critical sections, and/or has locks, or signals in flight
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    }
    fs_info_release(current->fs);
    current->fs = NULL;
    signal_pending = !!(current->pending & ~current->blocked);
    // sighand must be released below so it can be protected by pids_lock
    // since it can be accessed by other threads

    while((critical_region_count(current) > 1) ||
          (locks_held_count(current)) ||
          (current->process_info_being_read) ||
          (signal_pending)) { // Wait for now, task is in one or more critical// Wait for now, task is in one or more critical sections, and/or has locks, or signals in flight
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    }
    // save things that our parent might be interested in
    current->exit_code = status; // FIXME locking
    struct rusage_ rusage = rusage_get_current();
    simple_lockt(&current->group->lock, 0);
    rusage_add(&current->group->rusage, &rusage);
    struct rusage_ group_rusage = current->group->rusage;
    unlock(&current->group->lock);

    // the actual freeing needs pids_lock
    modify_critical_region_counter(current, 1, __FILE_NAME__, __LINE__);
    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    // release the sighand
    signal_pending = !!(current->pending & ~current->blocked);
    while((critical_region_count(current) > 2) ||
          (locks_held_count(current)) ||
          (current->process_info_being_read) ||
          (signal_pending)) { // Wait for now, task is in one or more critical // Wait for now, task is in one or more critical sections, and/or has locks, or signals in flight
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    }
    sighand_release(current->sighand);
    current->sighand = NULL;
    struct sigqueue *sigqueue, *sigqueue_tmp;
    list_for_each_entry_safe(&current->queue, sigqueue, sigqueue_tmp, queue) {
        list_remove(&sigqueue->queue);
        free(sigqueue);
    }
    struct task *leader = current->group->leader;

    // reparent children
    struct task *new_parent = find_new_parent(current);
    struct task *child, *tmp;
    list_for_each_entry_safe(&current->children, child, tmp, siblings) {
        child->parent = new_parent;
        list_remove(&child->siblings);
        list_add(&new_parent->children, &child->siblings);
    }
    
    signal_pending = !!(current->pending & ~current->blocked);
    
    while((critical_region_count(current) > 2) ||
          (locks_held_count(current)) ||
          (current->process_info_being_read) ||
          (signal_pending)) { // Wait for now, task is in one or more critical // Wait for now, task is in one or more critical sections, and/or has locks, or signals in flight
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(current->pending & ~current->blocked);
    }
    
    if (exit_tgroup(current)) {
        // notify parent that we died
        struct task *parent = leader->parent;
        if (parent == NULL) {
            // init died
            halt_system();
        } else {
            leader->zombie = true;
            notify(&parent->group->child_exit);
            struct siginfo_ info = {
                .code = SI_KERNEL_,
                .child.pid = current->pid,
                .child.uid = current->uid,
                .child.status = current->exit_code,
                .child.utime = clock_from_timeval(group_rusage.utime),
                .child.stime = clock_from_timeval(group_rusage.stime),
            };
            if (leader->exit_signal != 0)
                send_signal(parent, leader->exit_signal, info);
        }
        
        if (exit_hook != NULL)
            exit_hook(current, status);
    }

    modify_critical_region_counter(current, -1, __FILE_NAME__, __LINE__);
    vfork_notify(current);
    if(current != leader) 
        task_destroy(current);
    
    unlock_pids(&pids_lock);
    //atomic_l_unlockf();

EXIT:pthread_exit(NULL);
}

noreturn void do_exit_group(int status) {
    struct tgroup *group = current->group;
    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    simple_lockt(&group->lock, 0);
    if (!group->doing_group_exit) {
        group->doing_group_exit = true;
        group->group_exit_code = status;
    } else {
        status = group->group_exit_code;
    }

    // kill everyone else in the group
    struct task *task;
    int tmpvar = locks_held_count(current);
    
    if(tmpvar > 10000) { // If this happens, something has gone wrong  -mke
        tmpvar *= -1; // Convert to negative integer.  -mke
        modify_locks_held_count(current, tmpvar); // Reset to zero -mke
    }
    
    //while((critical_region_count(current))) { // Wait for now, task is in one or more critical sections, and/or has locks
     //   nanosleep(&lock_pause, NULL);
   // }
    modify_critical_region_counter(current, 1, __FILE_NAME__, __LINE__);
    list_for_each_entry(&group->threads, task, group_links) {
        task->exiting = true;
        deliver_signal(task, SIGKILL_, SIGINFO_NIL);
        //printk("INFO: Killing %s(%d)\n", current->comm, current->pid);
        task->group->stopped = false;
        notify(&task->group->stopped_cond);
    }

    unlock_pids(&pids_lock);
    modify_critical_region_counter(current, -1, __FILE_NAME__, __LINE__);
    unlock(&group->lock);
    if(current->pid <= MAX_PID) // abort if crazy.  -mke
        do_exit(status);
}

// always called from init process
static void halt_system(void) {
    // brutally murder everything
    // which will leave everything in an inconsistent state. I will solve this problem later.
    for (int i = 2; i < MAX_PID; i++) {
        struct task *task = pid_get_task(i);
        if (task != NULL)
            pthread_kill(task->thread, SIGKILL);
    }

    // unmount all filesystems
    simple_lockt(&mounts_lock, 0);
    struct mount *mount, *tmp;
    list_for_each_entry_safe(&mounts, mount, tmp, mounts) {
        mount_remove(mount);
    }
    unlock(&mounts_lock);
}

dword_t sys_exit(dword_t status) {
    STRACE("exit(%d)\n", status);
    do_exit(status << 8);
}

dword_t sys_exit_group(dword_t status) {
    STRACE("exit_group(%d)\n", status);
    do_exit_group(status << 8);
}

#define WNOHANG_ (1 << 0)
#define WUNTRACED_ (1 << 1)
#define WEXITED_ (1 << 2)
#define WCONTINUED_ (1 << 3)
#define WNOWAIT_ (1 << 24)
#define __WALL_ (1 << 30)

#define P_ALL_ 0
#define P_PID_ 1
#define P_PGID_ 2

// returns false if the task cannot be reaped and true if the task was reaped
static bool reap_if_zombie(struct task *task, struct siginfo_ *info_out, struct rusage_ *rusage_out, int options) {
    if (!task->zombie)
        return false;
    bool signal_pending = !!(task->pending & ~task->blocked);
    while(((signal_pending) ||
           (critical_region_count(task) > 1) ||
           (locks_held_count(task))) &&
           (task->pid > 10)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(task->pending & ~task->blocked);
    }
    complex_lockt(&task->group->lock, 0, __FILE_NAME__, __LINE__);

    dword_t exit_code = task->exit_code;
    if (task->group->doing_group_exit)
        exit_code = task->group->group_exit_code;
    info_out->child.status = exit_code;

    struct rusage_ rusage = task->group->rusage;
    if (!(options & WNOWAIT_)) {
        simple_lockt(&current->group->lock, 0);
        rusage_add(&current->group->children_rusage, &rusage);
        unlock(&current->group->lock);
    }
    if (rusage_out != NULL)
        *rusage_out = rusage;

    unlock(&task->group->lock);

    // WNOWAIT means don't destroy the child, instead leave it so it could be waited for again.
    if (options & WNOWAIT_)
        return true;

    // tear down group
   // lock(&pids_lock); //mkemkemke  Doesn't work
    //if(doEnableExtraLocking) //mke Doesn't work
     //   extra_lockf(task->pid);
    
    signal_pending = !!(task->pending & ~task->blocked);
    while(((signal_pending) ||
           (critical_region_count(task) > 1) ||
           (locks_held_count(task))) &&
           (task->pid > 10)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(task->pending & ~task->blocked);
    }
    cond_destroy(&task->group->child_exit);
    
    signal_pending = !!(task->pending & ~task->blocked);
    while(((signal_pending) ||
           (critical_region_count(task) > 1) ||
           (locks_held_count(task))) &&
           (task->pid > 10)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(task->pending & ~task->blocked);
    }
    task_leave_session(task);
    
    signal_pending = !!(task->pending & ~task->blocked);
    while(((signal_pending) ||
           (critical_region_count(task) > 1) ||
           (locks_held_count(task))) &&
           (task->pid > 10)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(task->pending & ~task->blocked);
    }
    list_remove(&task->group->pgroup);
    
    signal_pending = !!(task->pending & ~task->blocked);
    while(((signal_pending) ||
           (critical_region_count(task) > 1) ||
           (locks_held_count(task))) &&
           (task->pid > 10)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(task->pending & ~task->blocked);
    }
    free(task->group);
    
    signal_pending = !!(task->pending & ~task->blocked);
    while(((signal_pending) ||
           (critical_region_count(task) > 1) ||
           (locks_held_count(task))) &&
           (task->pid > 10)) {
        nanosleep(&lock_pause, NULL);
        signal_pending = !!(task->pending & ~task->blocked);
    }
    // &pids_lock is locked already at this point
    //complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    task_destroy(task);
    //unlock_pids(&pids_lock);
    
    return true;
}

static bool notify_if_stopped(struct task *task, struct siginfo_ *info_out) {
    complex_lockt(&task->group->lock, 0, __FILE_NAME__, __LINE__);
    bool stopped = task->group->stopped;
    unlock(&task->group->lock);
    if (!stopped || task->group->group_exit_code == 0)
        return false;
    dword_t exit_code = task->group->group_exit_code;
    task->group->group_exit_code = 0;
    info_out->child.status = exit_code;
    return true;
}

static bool reap_if_needed(struct task *task, struct siginfo_ *info_out, struct rusage_ *rusage_out, int options) {
    assert(task_is_leader(task));
    //if(doEnableExtraLocking)
    //    pthread_mutex_lock(&extra_lock);
    if ((options & WUNTRACED_ && notify_if_stopped(task, info_out)) ||
        (options & WEXITED_ && reap_if_zombie(task, info_out, rusage_out, options))) {
        info_out->sig = SIGCHLD_;
     //   if(doEnableExtraLocking)
       //     pthread_mutex_unlock(&extra_lock);
        return true;
    }
    simple_lockt(&task->ptrace.lock, 0);
    if (task->ptrace.stopped && task->ptrace.signal) {
        // I had this code here because it made something work, but it's now
        // making GDB think we support events (we don't). I can't remember what
        // it fixed but until then commenting it out for now.
        info_out->child.status = /* task->ptrace.trap_event << 16 |*/ task->ptrace.signal << 8 | 0x7f;
        task->ptrace.signal = 0;
        unlock(&task->ptrace.lock);
        //if(doEnableExtraLocking)
         //   pthread_mutex_unlock(&extra_lock);
        return true;
    }
    unlock(&task->ptrace.lock);
    //if(doEnableExtraLocking)
     //   pthread_mutex_unlock(&extra_lock);
    return false;
}

int do_wait(int idtype, pid_t_ id, struct siginfo_ *info, struct rusage_ *rusage, int options) {
    if (idtype != P_ALL_ && idtype != P_PID_ && idtype != P_PGID_)
        return _EINVAL;
    if (options & ~(WNOHANG_|WUNTRACED_|WEXITED_|WCONTINUED_|WNOWAIT_|__WALL_))
        return _EINVAL;

    complex_lockt(&pids_lock, 0, __FILE_NAME__, __LINE__);
    modify_critical_region_counter(current, 1, __FILE_NAME__, __LINE__);
    int err;
    bool got_signal = false;

retry:
    if (idtype != P_PID_) {
        // look for a zombie child
        bool no_children = true;
        struct task *parent;
        list_for_each_entry(&current->group->threads, parent, group_links) {
            struct task *task;
            list_for_each_entry(&current->children, task, siblings) {
                if (!task_is_leader(task))
                    continue;
                if (idtype == P_PGID_ && task->group->pgid != id)
                    continue;
                no_children = false;
                info->child.pid = task->pid;
                if (reap_if_needed(task, info, rusage, options))
                    goto found_something;
            }
        }
        err = _ECHILD;
        if (no_children)
            goto error;
    } else {
        // check if this child is a zombie
        struct task *task = pid_get_task_zombie(id);
        err = _ECHILD;
        if (task == NULL || task->parent == NULL || task->parent->group != current->group)
            goto error;
        task = task->group->leader;
        info->child.pid = id;
        if (reap_if_needed(task, info, rusage, options))
            goto found_something;
    }

    // WNOHANG leaves the info in an implementation-defined state. set the pid
    // to 0 so wait4 can pass that along correctly.
    info->child.pid = 0;
    if (options & WNOHANG_) {
        info->sig = SIGCHLD_;
        goto found_something;
    }

    err = _EINTR;
    if (got_signal)
        goto error;

    // no matching zombie found, wait for one
    if (wait_for(&current->group->child_exit, &pids_lock, NULL)) {
        // maybe we got a SIGCHLD! go through the loop one more time to make
        // sure the newly exited process is returned in that case.
        got_signal = true;
        goto retry;
    }
    goto retry;

    info->sig = SIGCHLD_;
found_something:
    modify_critical_region_counter(current, -1, __FILE_NAME__, __LINE__);
    unlock_pids(&pids_lock);
    return 0;

error:
    modify_critical_region_counter(current, -1, __FILE_NAME__, __LINE__);
    unlock_pids(&pids_lock);
    return err;
}

dword_t sys_waitid(int_t idtype, pid_t_ id, addr_t info_addr, int_t options) {
    STRACE("waitid(%d, %d, %#x, %#x)", idtype, id, info_addr, options);
    struct siginfo_ info = {};
    int_t res = 0;
    TASK_MAY_BLOCK {
        res = do_wait(idtype, id, &info, NULL, options);
    }
    if (res < 0 || (res == 0 && info.child.pid == 0))
        return res;
    if (info_addr != 0 && user_put(info_addr, info))
        return _EFAULT;
    return 0;
}

dword_t sys_wait4(pid_t_ id, addr_t status_addr, dword_t options, addr_t rusage_addr) {
    STRACE("wait4(%d, %#x, %#x, %#x)", id, status_addr, options, rusage_addr);
    if (options & WNOWAIT_)
        return _EINVAL;

    int idtype;
    if (id > 0)
        idtype = P_PID_;
    else if (id == -1)
        idtype = P_ALL_;
    else {
        idtype = P_PGID_;
        if (id == 0)
            id = current->group->pgid;
        else
            id = -id;
    }

    struct siginfo_ info = {.child.pid = 0xbaba};
    struct rusage_ rusage;
    int_t res = 0;
    TASK_MAY_BLOCK {
        res = do_wait(idtype, id, &info, &rusage, options | WEXITED_);
    }
    if (res < 0 || (res == 0 && info.child.pid == 0))
        return res;
    if (status_addr != 0 && user_put(status_addr, info.child.status))
        return _EFAULT;
    if (rusage_addr != 0 && user_put(rusage_addr, rusage))
        return _EFAULT;
    return info.child.pid;
}

dword_t sys_waitpid(pid_t_ pid, addr_t status_addr, dword_t options) {
    return sys_wait4(pid, status_addr, options, 0);
}
