#include "fs/proc.h"
#include "fs/proc/ish.h"
#include "fs/proc/net.h"
#include "kernel/errno.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#import <ifaddrs.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <net/if_var.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include "debug.h"

const char *proc_ish_version = "";
char **(*get_all_defaults_keys)(void);
char *(*get_friendly_name)(const char *name);
char *(*get_underlying_name)(const char *name);
bool (*get_user_default)(const char *name, char **buffer, size_t *size);
bool (*set_user_default)(const char *name, char *buffer, size_t size);
bool (*remove_user_default)(const char *name);
char *(*get_documents_directory)(void);

static int proc_ish_show_colors(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    proc_printf(buf,
                "\x1B[30m" "iSH" "\x1B[39m "
                "\x1B[31m" "iSH" "\x1B[39m "
                "\x1B[32m" "iSH" "\x1B[39m "
                "\x1B[33m" "iSH" "\x1B[39m "
                "\x1B[34m" "iSH" "\x1B[39m "
                "\x1B[35m" "iSH" "\x1B[39m "
                "\x1B[36m" "iSH" "\x1B[39m "
                "\x1B[37m" "iSH" "\x1B[39m" "\n\x1B[7m"
                "\x1B[40m" "iSH" "\x1B[39m "
                "\x1B[41m" "iSH" "\x1B[39m "
                "\x1B[42m" "iSH" "\x1B[39m "
                "\x1B[43m" "iSH" "\x1B[39m "
                "\x1B[44m" "iSH" "\x1B[39m "
                "\x1B[45m" "iSH" "\x1B[39m "
                "\x1B[46m" "iSH" "\x1B[39m "
                "\x1B[47m" "iSH" "\x1B[39m" "\x1B[0m\x1B[1m\n"
                "\x1B[90m" "iSH" "\x1B[39m "
                "\x1B[91m" "iSH" "\x1B[39m "
                "\x1B[92m" "iSH" "\x1B[39m "
                "\x1B[93m" "iSH" "\x1B[39m "
                "\x1B[94m" "iSH" "\x1B[39m "
                "\x1B[95m" "iSH" "\x1B[39m "
                "\x1B[96m" "iSH" "\x1B[39m "
                "\x1B[97m" "iSH" "\x1B[39m" "\n\x1B[7m"
                "\x1B[100m" "iSH" "\x1B[39m "
                "\x1B[101m" "iSH" "\x1B[39m "
                "\x1B[102m" "iSH" "\x1B[39m "
                "\x1B[103m" "iSH" "\x1B[39m "
                "\x1B[104m" "iSH" "\x1B[39m "
                "\x1B[105m" "iSH" "\x1B[39m "
                "\x1B[106m" "iSH" "\x1B[39m "
                "\x1B[107m" "iSH" "\x1B[39m" "\x1B[0m\n"
                );
    return 0;
}

static int proc_ish_show_documents(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    char *directory = get_documents_directory();
    proc_printf(buf, "%s\n", directory);
    free(directory);
    return 0;
}

static void proc_ish_defaults_getname(struct proc_entry *entry, char *buf) {
    strcpy(buf, entry->name);
}

static int proc_ish_defaults_readlink(struct proc_entry *entry, char *buf) {
    char *name = get_underlying_name(entry->name);
    sprintf(buf, "../.defaults/%s", name);
    free(name);
    return 0;
}

static int proc_ish_underlying_defaults_show(struct proc_entry *entry, struct proc_data *data) {
    size_t size;
    char *buffer;
    if (!get_user_default(entry->name, &buffer, &size))
        return _EIO;
    proc_buf_append(data, buffer, size);
    free(buffer);
    return 0;
}

static int proc_ish_underlying_defaults_update(struct proc_entry *entry, struct proc_data *data) {
    if (!set_user_default(entry->name, data->data, data->size)) //mkemkemke Set Defaults
        return _EIO;
    return 0;
}

static int proc_ish_underlying_defaults_unlink(struct proc_entry *entry) {
    return remove_user_default(entry->name) ? 0 : _EIO;
}

static int proc_ish_defaults_unlink(struct proc_entry *entry) {
    char *name = get_underlying_name(entry->name);
    int err = remove_user_default(name) ? 0 : _EIO;
    free(name);
    return err;
}

struct proc_dir_entry proc_ish_underlying_defaults_fd = { NULL,
    .getname = proc_ish_defaults_getname,
    .show = proc_ish_underlying_defaults_show,
    .update = proc_ish_underlying_defaults_update,
    .unlink = proc_ish_underlying_defaults_unlink,
};

struct proc_dir_entry proc_ish_defaults_fd = { NULL, S_IFLNK,
    .getname = proc_ish_defaults_getname,
    .readlink = proc_ish_defaults_readlink,
    .unlink = proc_ish_defaults_unlink,
};

static void get_child_names(struct proc_entry *entry, unsigned long index) {
    if (index == 0 || entry->child_names == NULL) {
        if (entry->child_names != NULL)
            free_string_array(entry->child_names);
        entry->child_names = get_all_defaults_keys();
    }
}

static bool proc_ish_underlying_defaults_readdir(struct proc_entry *entry, unsigned long *index, struct proc_entry *next_entry) {
    get_child_names(entry, *index);
    if (entry->child_names[*index] == NULL)
        return false;
    next_entry->meta = &proc_ish_underlying_defaults_fd;
    next_entry->name = strdup(entry->child_names[*index]);
    (*index)++;
    return true;
}

static bool proc_ish_defaults_readdir(struct proc_entry *entry, unsigned long *index, struct proc_entry *next_entry) {
    get_child_names(entry, *index);
    char *friendly_name;
    do {
        const char *name = entry->child_names[*index];
        if (name == NULL)
            return false;
        friendly_name = get_friendly_name(name);
        (*index)++;
    } while (friendly_name == NULL);
    next_entry->meta = &proc_ish_defaults_fd;
    next_entry->name = friendly_name;
    return true;
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

void parse_if_flags(int flags, char *build_string, size_t size) {
    int first = 1;  // No comma on the first flag
    memset(build_string, 0, size);  // Ensure the string is initialized to zero

    if(flags & IFF_UP) {
        first = 0;
        strcat(build_string, "UP");
    }
    
    if(flags & IFF_BROADCAST) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "BROADCAST");
    }
    
    if(flags & IFF_DEBUG) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "DEBUG");
    }
    
    if(flags & IFF_LOOPBACK) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "LOOPBACK");
    }
    
    if(flags & IFF_POINTOPOINT) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "POINTOPOINT");
    }
    
    if(flags & IFF_NOTRAILERS) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "NOTRAILERS");
    }
    
    if(flags & IFF_RUNNING) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "RUNNING");
    }
    
    if(flags & IFF_NOARP) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "NOARP");
    }
    
    if(flags & IFF_PROMISC) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "PROMISC");
    }
    
    if(flags & IFF_ALLMULTI) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "ALLMULTI");
    }
    
    if(flags & IFF_MULTICAST) {
        if(!first) {
            strcat(build_string,",");
        }
        first = 0;
        strcat(build_string, "MULTICAST");
    }
}

static int proc_ish_show_ips(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    proc_printf(buf, "Iface        IP                                         Broadcast/Multicast                         Family    Flags\n");
    struct ifaddrs *addrs;
    int ret = getifaddrs(&addrs);
    if (ret != 0) {
        printk("ERROR: Failed to get network interfaces, error: %s\n", strerror(errno));
        return ret;
    }

    const struct ifaddrs *cursor = addrs;
    char type[9];
    char int_ip[100];
    char int_dstaddr[100];
    char int_flags[250];

    while (cursor != NULL) {
        if ((cursor->ifa_addr->sa_family == AF_INET) || (cursor->ifa_addr->sa_family == AF_INET6)) {
            if(cursor->ifa_addr->sa_family == AF_INET) {
                strncpy(type, "IF_INET", 8);
                type[8] = '\0';
            } else {
                strncpy(type, "IF_INET6", 8);
                type[8] = '\0';
            }
            get_ip_str(cursor->ifa_addr, int_ip, 100);
            if(cursor->ifa_dstaddr != NULL) {
                get_ip_str(cursor->ifa_dstaddr, int_dstaddr, 100);
            } else {
                strcpy(int_dstaddr," ");
            }
            parse_if_flags(cursor->ifa_flags, int_flags, sizeof(int_flags));
            proc_printf(buf, "%-10.10s   %-40s   %-40s    %-8s  %-60s\n",
                        cursor->ifa_name,
                        int_ip,
                        int_dstaddr,
                        type,
                        int_flags
            );
        }
        cursor = cursor->ifa_next;
    }

    freeifaddrs(addrs);
    return 0;
}


static int proc_ish_show_version(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    proc_printf(buf, "%s\n", proc_ish_version);
    return 0;
}

struct proc_children proc_ish_children = PROC_CHILDREN({
    {"colors", .show = proc_ish_show_colors},
    {".defaults", S_IFDIR, .readdir = proc_ish_underlying_defaults_readdir},
    {"defaults", S_IFDIR, .readdir = proc_ish_defaults_readdir},
    {"documents", .show = proc_ish_show_documents},
    {"ips", .show = proc_ish_show_ips},
    {"version", .show = proc_ish_show_version},
});
