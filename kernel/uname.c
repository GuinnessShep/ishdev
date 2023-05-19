#include <sys/utsname.h>
#include <string.h>
#include "kernel/calls.h"
#include "platform/platform.h"

#if __APPLE__
#include <sys/sysctl.h>
#elif __linux__
#include <sys/sysinfo.h>
#endif

const char *uname_version = "iSH-AOK";
char *uname_hostname_override = NULL;


#define BUILD_DATE_SIZE 100

void do_uname(struct uname *uts) {
    if(uts == NULL) {
        return;
    }

    struct utsname real_uname;
    if (uname(&real_uname) == -1) {
        return;  // or handle error as appropriate
    }

    const char *hostname = uname_hostname_override ? uname_hostname_override : real_uname.nodename;
    
    // Get current date and format it in a sane way
    char build_date[100];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    if(t == NULL) {
        return;  // or handle error as appropriate
    }
    strftime(build_date, sizeof(build_date), "%Y-%m-%d %H:%M", t);

    static const struct uname u = {
        .arch = "i686",
        .domain = "(none)",
        .release = "4.20.69-ish_aok",
        .system = "Linux"
    };
    *uts = u;
    strncpy(uts->hostname, hostname, sizeof(uts->hostname) - 1);
    uts->hostname[sizeof(uts->hostname) - 1] = '\0';
    snprintf(uts->version, sizeof(uts->version), "%s %s", uname_version, build_date);
}


dword_t sys_uname(addr_t uts_addr) {
    struct uname uts;
    do_uname(&uts);
    if (user_put(uts_addr, uts))
        return _EFAULT;
    return 0;
}

dword_t sys_sethostname(addr_t hostname_addr, dword_t hostname_len) {
    if(current->uid != 0) {
        return _EPERM;
    } else {
        free(uname_hostname_override);
        uname_hostname_override = malloc(hostname_len + 1);
        int result = 0;
        // user_read(addr, &(var), sizeof(var))
        result = user_read(hostname_addr, uname_hostname_override, hostname_len + 1);
            
        return result;
    }
}

#if __APPLE__
static uint64_t get_total_ram() {
    uint64_t total_ram;
    sysctl((int []) {CTL_DEBUG, HW_PHYSMEM}, 2, &total_ram, NULL, NULL, 0);
    return total_ram;
}
static void sysinfo_specific(struct sys_info *info) {
    info->totalram = (dword_t)get_total_ram();
    // TODO: everything else
}
#elif __linux__
static void sysinfo_specific(struct sys_info *info) {
    struct sysinfo host_info;
    sysinfo(&host_info);
    info->totalram = host_info.totalram;
    info->freeram = host_info.freeram;
    info->sharedram = host_info.sharedram;
    info->totalswap = host_info.totalswap;
    info->freeswap = host_info.freeswap;
    info->procs = host_info.procs;
    info->totalhigh = host_info.totalhigh;
    info->freehigh = host_info.freehigh;
    info->mem_unit = host_info.mem_unit;
}
#endif

dword_t sys_sysinfo(addr_t info_addr) {
    struct sys_info info = {0};
    struct uptime_info uptime = get_uptime();
    info.uptime = (dword_t)uptime.uptime_ticks;
    info.loads[0] = (dword_t)uptime.load_1m;
    info.loads[1] = (dword_t)uptime.load_5m;
    info.loads[2] = (dword_t)uptime.load_15m;
    sysinfo_specific(&info);

    if (user_put(info_addr, info))
        return _EFAULT;
    return 0;
}
