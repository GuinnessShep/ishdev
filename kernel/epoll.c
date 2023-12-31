#include "kernel/calls.h"
#include "fs/poll.h"

static struct fd_ops epoll_ops;

extern bool doEnableMulticore;

fd_t sys_epoll_create(int_t flags) {
    STRACE("epoll_create(%#x)", flags);
    if (flags & ~(O_CLOEXEC_))
        return _EINVAL;

    struct fd *fd = adhoc_fd_create(&epoll_ops);
    if (fd == NULL)
        return _ENOMEM;
    struct poll *poll = poll_create();
    if (IS_ERR(poll))
        return PTR_ERR(poll);
    fd->epollfd.poll = poll;
    return f_install(fd, flags);
}
fd_t sys_epoll_create0() {
    return sys_epoll_create(0);
}

struct epoll_event_ {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));

#define EPOLL_CTL_ADD_ 1
#define EPOLL_CTL_DEL_ 2
#define EPOLL_CTL_MOD_ 3
#define EPOLLET_ (1 << 31)
#define EPOLLONESHOT_ (1 << 30)

int_t sys_epoll_ctl(fd_t epoll_f, int_t op, fd_t f, addr_t event_addr) {
    STRACE("epoll_ctl(%d, %d, %d, %#x)", epoll_f, op, f, event_addr);
    struct fd *epoll = f_get(epoll_f);
    if (epoll == NULL)
        return _EBADF;
    if (epoll->ops != &epoll_ops)
        return _EINVAL;
    struct fd *fd = f_get(f);
    if (fd == NULL)
        return _EBADF;

    if (op == EPOLL_CTL_DEL_)
        return poll_del_fd(epoll->epollfd.poll, fd);

    struct epoll_event_ event;
    if (user_get(event_addr, event))
        return _EFAULT;
    STRACE(" {events: %#x, data: %#x}", event.events, event.data);

    if (op == EPOLL_CTL_ADD_) {
        if (poll_has_fd(epoll->epollfd.poll, fd))
            return _EEXIST;
        return poll_add_fd(epoll->epollfd.poll, fd, event.events, (union poll_fd_info) event.data);
    } else {
        return poll_mod_fd(epoll->epollfd.poll, fd, event.events, (union poll_fd_info) event.data);
    }
}

struct epoll_context {
    struct epoll_event_ *events;
    int n;
    int max_events;
};

static int epoll_callback(void *context, int types, union poll_fd_info info) {
    struct epoll_context *c = context;
    if (c->n >= c->max_events)
        return 0;
    c->events[c->n++] = (struct epoll_event_) {.events = types, .data = info.num};
    return 1;
}

int_t sys_epoll_wait(fd_t epoll_f, addr_t events_addr, int_t max_events, int_t timeout) {
    STRACE("epoll_wait(%d, %#x, %d, %d)", epoll_f, events_addr, max_events, timeout);
    struct fd *epoll = f_get(epoll_f);
    if (epoll == NULL)
        return _EBADF;
    if (epoll->ops != &epoll_ops)
        return _EINVAL;

    struct timespec timeout_ts;
    if (timeout >= 0) {
        timeout_ts.tv_sec = timeout / 1000;
        timeout_ts.tv_nsec = (timeout % 1000) * 1000000;
    }
    if (max_events <= 0)
        return _EINVAL;
    struct epoll_event_ events[max_events];

    struct epoll_context context = {.events = events, .n = 0, .max_events = max_events};
    STRACE("...\n");
    int res;
    if(!doEnableMulticore) {
        struct timespec mytime;
        mytime.tv_sec = 2;
        mytime.tv_nsec = 0;
        res = poll_wait(epoll->epollfd.poll, epoll_callback, &context, &mytime); // This is arguably evil, but it makes go work much better and I haven't found a downside yet.  -mke
    } else {
        res = poll_wait(epoll->epollfd.poll, epoll_callback, &context, timeout < 0 ? NULL : &timeout_ts);
    }
    STRACE("%d end epoll_wait", current->pid);
    if (res >= 0) {
        for (int i = 0; i < res; i++) {
            STRACE(" {events: %#x, data: %#x}", events[i].events, events[i].data);
        }
        if (user_write(events_addr, events, sizeof(struct epoll_event_) * res))
            return _EFAULT;
    }
    return res;
}

int_t sys_epoll_pwait(fd_t epoll_f, addr_t events_addr, int_t max_events, int_t timeout, addr_t sigmask_addr, dword_t sigsetsize) {
    sigset_t_ mask;
    if (sigmask_addr != 0) {
        if (sigsetsize != sizeof(sigset_t_))
            return _EINVAL;
        if (user_get(sigmask_addr, mask))
            return _EFAULT;
        sigmask_set_temp(mask);
    }

    return sys_epoll_wait(epoll_f, events_addr, max_events, timeout);
}

static int epoll_close(struct fd *fd) {
    poll_destroy(fd->epollfd.poll);
    return 0;
}

static struct fd_ops epoll_ops = {
    .close = epoll_close,
};
