#include <stddef.h>
#include <stdbool.h>

//extern static ssize_t proc_show_dev(struct proc_entry * UNUSED(entry), char *buf);
extern bool proc_net_readdir(struct proc_entry * UNUSED(entry), unsigned long *index, struct proc_entry *next_entry);
//extern bool (*remove_user_default)(const char *name);
