#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <inttypes.h>
#include <string.h>
#include "kernel/calls.h"
#include "fs/proc.h"
#include "platform/platform.h"

#import <ifaddrs.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <net/if_var.h>

// Partially cribbed from https://github.com/ish-app/ish/pull/315/commits/4a3d96b4ed81470216534d299b921ba3c09ba03f#diff-8c3246e6b14ecb993cb4bf40b3d502a201566f225e339aa09cff57871f0d6351

#pragma mark - /proc/net

/*
 00000000000000000000000000000001 01 80 10 80       lo
 */
static int proc_show_if_inet6(struct proc_entry * UNUSED(entry), struct proc_data *buf) {
    struct ifaddrs *addrs;
    size_t needed; // How much buffer do we need to allocate
    // char *mybuf;
    
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS};
    // sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &needed, NULL, 0) < 0) {
       printk("error in route-sysctl-estimate");
       //return 0;
    } else {
       //printk("%s\n", )
    }
    
    bool success = (getifaddrs(&addrs) == 0);
    unsigned count = 0;
    if (success) {
        const struct ifaddrs *cursor = addrs;
        while (cursor != NULL) {
            //count++;
            if (cursor->ifa_addr->sa_family == AF_LINK) {
                proc_printf(buf, "00000000000000000000000000000001 %02x 80 10 80       %s\n", count++, cursor->ifa_name);
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    
    return 0;
}

static int proc_show_arp(struct proc_entry * UNUSED(entry), struct proc_data *buf) {
    /*
     IP address       HW type     Flags       HW address            Mask     Device
     10.211.55.1      0x1         0x2         00:1c:42:00:00:18     *        eth0
     */
    proc_printf(buf, "IP address       HW type     Flags       HW address            Mask     Device\n");
    proc_printf(buf, "192.168.1.1      0x1         0x2         00:BE:EF:CA:FE:00     *        en0\n");
    return 0;
}

static int proc_show_raw(struct proc_entry *UNUSED(entry), struct proc_data *UNUSED(buf)) {
    return 0;
}

static int proc_show_raw6(struct proc_entry *UNUSED(entry), struct proc_data *UNUSED(buf)) {
    return 0;
}

static int proc_show_tcp(struct proc_entry *UNUSED(entry), struct proc_data *UNUSED(buf)) {
    return 0;
}

static int proc_show_tcp6(struct proc_entry *UNUSED(entry), struct proc_data *UNUSED(buf)) {
    return 0;
}

static int proc_show_udp(struct proc_entry *UNUSED(entry), struct proc_data *UNUSED(buf)) {
    return 0;
}

static int proc_show_udp6(struct proc_entry *UNUSED(entry), struct proc_data *UNUSED(buf)) {
    return 0;
}


static int proc_show_route(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    
    proc_printf(buf, "Iface    Destination    Gateway     Flags    RefCnt    Use    Metric    Mask        MTU    Window    IRTT \n");
    
    struct ifaddrs *addrs;
    int ret = getifaddrs(&addrs);
    if (ret != 0) {
        printk("ERROR: Failed to get network interfaces, error: %s\n", strerror(ret));
        return ret;
    }

    struct ifaddrs *cursor = addrs;
    while (cursor != NULL) {
        if (cursor->ifa_addr == NULL) {
            cursor = cursor->ifa_next;
            continue;
        }

        int anything_but_loopback = strcmp(cursor->ifa_name, "lo0");
        if ((cursor->ifa_addr->sa_family == AF_LINK) && (anything_but_loopback)) {
            struct if_data *stats = (struct if_data *)cursor->ifa_data;
            if (stats == NULL) {
                cursor = cursor->ifa_next;
                continue;
            }

            proc_printf(buf, "%-6.6s  %8.8d   %8.8d  %+4.4x  %1.1d  %3.3d  %8.8d  %8.8d  %1.1d  %1.1d  %1.1d\n",
                        cursor->ifa_name,
                        0, // Destination
                        0, // Gateway IP
                        cursor->ifa_flags,
                        0, // RefCnt
                        0, // Use
                        (unsigned long)stats->ifi_metric,
                        0, // Mask
                        (unsigned long)stats->ifi_mtu,
                        0, // Window
                        0  // IRTT
            );
        }
        cursor = cursor->ifa_next;
    }
    freeifaddrs(addrs);

    return 0;
}


static int proc_show_dev(struct proc_entry * UNUSED(entry), struct proc_data *buf) {
    proc_printf(buf, "Inter-|   Receive                            "
                 "                    |  Transmit\n"
                 " face |bytes    packets errs drop fifo frame "
                 "compressed multicast|bytes    packets errs "
                 "drop fifo colls carrier compressed\n");

    struct ifaddrs *addrs;
    int ret = getifaddrs(&addrs);
    if (ret != 0) {
        printk("ERROR: Failed to get network interfaces, error: %s\n", strerror(ret));
        return ret;
    }

    struct ifaddrs *cursor = addrs;
    while (cursor != NULL) {
        if (cursor->ifa_addr == NULL) {
            cursor = cursor->ifa_next;
            continue;
        }

        if (cursor->ifa_addr->sa_family == AF_LINK) {
            struct if_data *stats = (struct if_data *)cursor->ifa_data;
            if (stats != NULL) {
                proc_printf(buf, "%6s:%8llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu %8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
                            cursor->ifa_name,
                            (unsigned long long)stats->ifi_ibytes,
                            (unsigned long long)stats->ifi_ipackets,
                            (unsigned long long)stats->ifi_ierrors,
                            (unsigned long long)stats->ifi_iqdrops,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)stats->ifi_imcasts,
                            (unsigned long long)stats->ifi_obytes,
                            (unsigned long long)stats->ifi_opackets,
                            (unsigned long long)stats->ifi_oerrors,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)stats->ifi_collisions,
                            (unsigned long long)(stats->ifi_ierrors + stats->ifi_oerrors),
                            (unsigned long long)0);
            } else {
                proc_printf(buf, "%6s:%8llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu %8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
                            cursor->ifa_name,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0,
                            (unsigned long long)0);
            }
        }
        cursor = cursor->ifa_next;
    }
    freeifaddrs(addrs);

    return 0;
}

#define PROC_NET_LEN sizeof(proc_net_entries) / sizeofproc_net_entries
/*
dr-xr-xr-x 5 root root 0 Jun  5 10:55 dev_snmp6
dr-xr-xr-x 3 root root 0 Jun  5 10:55 ipconfig
dr-xr-xr-x 3 root root 0 Jun  5 10:55 netfilter
dr-xr-xr-x 4 root root 0 Jun  5 10:55 nfsfs
dr-xr-xr-x 8 root root 0 Jun  5 10:55 rpc
dr-xr-xr-x 5 root root 0 Jun  5 10:55 stat
dr-xr-xr-x 3 root root 0 Jun  5 10:55 vlan
*/
static bool net_show_net_snmp6(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_ipconfig(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_netfilter(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_nfsfs(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_rpc(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_stat(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_unix(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

static bool net_show_vlan(struct proc_entry *UNUSED(entry), unsigned long *UNUSED(index), struct proc_entry *UNUSED(next_entry)) {
    return 0;
}

struct proc_children proc_net_children = PROC_CHILDREN({
    {"arp", .show = proc_show_arp},
    {"ipconfig", S_IFDIR, .readdir = net_show_ipconfig},
    {"net_snmp6", S_IFDIR, .readdir = net_show_net_snmp6},
    {"netfilter", S_IFDIR, .readdir = net_show_netfilter},
    {"nfsfs", S_IFDIR, .readdir = net_show_nfsfs},
    {"raw", .show = proc_show_raw},
    {"raw6", .show = proc_show_raw6},
    {"rpc", S_IFDIR, .readdir = net_show_rpc},
    {"stat", S_IFDIR, .readdir = net_show_stat},
    {"tcp", .show = proc_show_tcp},
    {"tcp6", .show = proc_show_tcp6},
    {"udp", .show = proc_show_udp},
    {"udp6", .show = proc_show_udp6},
    {"unix", S_IFDIR, .readdir = net_show_unix},
    {"vlan", S_IFDIR, .readdir = net_show_vlan},
    //{"defaults",  .show = proc_show_dev},
    {"dev", .show = proc_show_dev},
    {"route", .show = proc_show_route },
    {"if_inet6", .show = proc_show_if_inet6 },
});
