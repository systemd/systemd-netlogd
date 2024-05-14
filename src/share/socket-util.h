/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>

#include "macro.h"
#include "util.h"

union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_nl nl;
        struct sockaddr_storage storage;
        struct sockaddr_ll ll;
};

typedef struct SocketAddress {
        union sockaddr_union sockaddr;

        /* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
        socklen_t size;

        /* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
        int type;

        /* Socket protocol, IPPROTO_xxx, usually 0, except for netlink */
        int protocol;
} SocketAddress;

typedef enum SocketAddressBindIPv6Only {
        SOCKET_ADDRESS_DEFAULT,
        SOCKET_ADDRESS_BOTH,
        SOCKET_ADDRESS_IPV6_ONLY,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_INVALID = -1
} SocketAddressBindIPv6Only;

#define socket_address_family(a) ((a)->sockaddr.sa.sa_family)

int socket_address_parse(SocketAddress *a, const char *s);

int socket_address_listen(
                const SocketAddress *a,
                int flags,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool reuse_port,
                bool free_bind,
                bool transparent,
                mode_t directory_mode,
                mode_t socket_mode,
                const char *label);
bool socket_ipv6_is_supported(void);

int fd_inc_sndbuf(int fd, size_t n);
int fd_inc_rcvbuf(int fd, size_t n);

#define CMSG_FOREACH(cmsg, mh)                                          \
        for ((cmsg) = CMSG_FIRSTHDR(mh); (cmsg); (cmsg) = CMSG_NXTHDR((mh), (cmsg)))

/* Covers only file system and abstract AF_UNIX socket addresses, but not unnamed socket addresses. */
#define SOCKADDR_UN_LEN(sa)                                             \
        ({                                                              \
                const struct sockaddr_un *_sa = &(sa);                  \
                assert(_sa->sun_family == AF_UNIX);                     \
                offsetof(struct sockaddr_un, sun_path) +                \
                        (_sa->sun_path[0] == 0 ?                        \
                         1 + strnlen(_sa->sun_path+1, sizeof(_sa->sun_path)-1) : \
                         strnlen(_sa->sun_path, sizeof(_sa->sun_path))); \
        })

int sockaddr_pretty(const struct sockaddr *_sa, socklen_t salen, bool translate_ipv6, bool include_port, char **ret);

static inline int setsockopt_int(int fd, int level, int optname, int value) {
        if (setsockopt(fd, level, optname, &value, sizeof(value)) < 0)
                return -errno;

        return 0;
}

static inline int getsockopt_int(int fd, int level, int optname, int *ret) {
        int v;
        socklen_t sl = sizeof(v);

        if (getsockopt(fd, level, optname, &v, &sl) < 0)
                return negative_errno();
        if (sl != sizeof(v))
                return -EIO;

        *ret = v;
        return 0;
}

int fd_set_sndbuf(int fd, size_t n, bool increase);
