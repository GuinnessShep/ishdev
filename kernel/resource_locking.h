//#include "util/sync.h"
// Because sometimes we can't #include "kernel/task.h" -mke

extern unsigned critical_region_count(struct task*);
//#define critical_region_modify(task, int) __modify_critical_region_count(task, int, __FILE_NAME__, __LINE__)
extern void critical_region_modify(struct task*, int, char*, int);
extern unsigned locks_held_count(struct task*);
extern void modify_locks_held_count(struct task*, int);
extern bool current_is_valid(void);
//extern static inline void atomic_l_lockf(wrlock_t *lock, const char *lname, const char *file, int line);
//extern static inline void atomic_l_unlockf(wrlock_t *lock, const char *lname, const char *file, int line);

