//#include "util/sync.h"
// Because sometimes we can't #include "kernel/task.h" -mke

extern unsigned critical_region_count(struct task*);
//#define modify_critical_region_counter(task, int) __modify_critical_region_count(task, int, __FILE_NAME__, __LINE__)
extern void modify_critical_region_counter(struct task*, int, char*, int);
extern unsigned locks_held_count(struct task*);
extern void modify_locks_held_count(struct task*, int);
extern bool current_is_valid(void);

