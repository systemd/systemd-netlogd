/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/tcp.h>
#include <poll.h>
#include <stddef.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "netlog-manager.h"
#include "netlog-network.h"
#include "netlog-protocol.h"

#define RFC_5424_NILVALUE "-"
#define RFC_5424_PROTOCOL 1

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

static int sendmsg_loop(Manager *m, struct msghdr *mh) {
        ssize_t n;
        int r;

        assert(m);
        assert(m->socket >= 0);
        assert(mh);

        for (;;) {
                n = sendmsg(m->socket, mh, MSG_NOSIGNAL);
                if (n >= 0) {
                        log_debug("Successful sendmsg: %zd bytes", n);
                        return 0;
                }

                if (errno == EINTR)
                        continue;

                if (errno != EAGAIN)
                        return -errno;

                r = fd_wait_for_event(m->socket, POLLOUT, SEND_TIMEOUT_USEC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }

        return 0;
}

int network_send(Manager *m, struct iovec *iovec, unsigned n_iovec) {
        struct msghdr mh = {
                .msg_iov = iovec,
                .msg_iovlen = n_iovec,
        };

        assert(m);
        assert(iovec);
        assert(n_iovec > 0);

        if (m->address.sockaddr.sa.sa_family == AF_INET) {
                mh.msg_name = &m->address.sockaddr.sa;
                mh.msg_namelen = sizeof(m->address.sockaddr.in);
        } else if (m->address.sockaddr.sa.sa_family == AF_INET6) {
                mh.msg_name = &m->address.sockaddr.sa;
                mh.msg_namelen = sizeof(m->address.sockaddr.in6);
        } else
                return -EAFNOSUPPORT;

        return sendmsg_loop(m, &mh);
}
int manager_push_to_network(Manager *m,
                            int severity,
                            int facility,
                            const char *identifier,
                            const char *message,
                            const char *hostname,
                            const char *pid,
                            const struct timeval *tv,
                            const char *syslog_structured_data,
                            const char *syslog_msgid) {

        int r;

        assert(m);

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_DTLS:
                        if (!m->dtls->connected) {
                                r = manager_connect(m);
                                if (r < 0)
                                        return r;
                        }

                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TLS:
                        if (!m->tls->connected) {
                                r = manager_connect(m);
                                if (r < 0)
                                        return r;
                        }
                        break;
                default:
                        if (!m->connected) {
                                r = manager_connect(m);
                                if (r < 0)
                                        return r;
                        }
                        break;
        }

        if (m->log_format == SYSLOG_TRANSMISSION_LOG_FORMAT_RFC_5424)
               r = format_rfc5424(m, severity, facility, identifier, message, hostname, pid, tv, syslog_structured_data, syslog_msgid);
        else
               r = format_rfc3339(m, severity, facility, identifier, message, hostname, pid, tv);

        if (r < 0)
               return r;

        return 0;
}

void manager_close_network_socket(Manager *m) {
       assert(m);

        if (m->protocol == SYSLOG_TRANSMISSION_PROTOCOL_TCP && m->socket >= 0) {
                int r = shutdown(m->socket, SHUT_RDWR);
                if (r < 0)
                        log_error_errno(errno, "Failed to shutdown netlog socket: %m");
        }

        m->connected = false;
        m->socket = safe_close(m->socket);
}

int manager_network_connect_socket(Manager *m) {
        _cleanup_free_ char *pretty = NULL;
        union sockaddr_union sa;
        socklen_t salen;
        int r;

        assert(m);
        assert(m->socket >= 0);

        switch (m->address.sockaddr.sa.sa_family) {
                case AF_INET:
                        sa = (union sockaddr_union) {
                                .in.sin_family = m->address.sockaddr.sa.sa_family,
                                .in.sin_port = m->address.sockaddr.in.sin_port,
                                .in.sin_addr = m->address.sockaddr.in.sin_addr,
                        };
                        salen = sizeof(sa.in);
                        break;
                case AF_INET6:
                        sa = (union sockaddr_union) {
                                .in6.sin6_family = m->address.sockaddr.sa.sa_family,
                                .in6.sin6_port = m->address.sockaddr.in6.sin6_port,
                                .in6.sin6_addr = m->address.sockaddr.in6.sin6_addr,
                        };
                        salen = sizeof(sa.in6);
                        break;
                default:
                        return -EAFNOSUPPORT;
        }

        r = sockaddr_pretty(&m->address.sockaddr.sa, salen, true, true, &pretty);
        if (r < 0)
                return r;

        log_debug("Connecting to remote server: '%s'", pretty);

        r = connect(m->socket, &m->address.sockaddr.sa, salen);
        if (r < 0 && errno != EINPROGRESS)
                return log_error_errno(errno, "Failed to connect to remote server='%s': %m", pretty);

        if (errno != EINPROGRESS)
                log_debug("Connected to remote server: '%s'", pretty);
        else
                log_debug("Connection in progress to remote server: '%s'", pretty);

        return 0;
}

static int apply_tcp_socket_options(Manager *m){
        int r;

        assert(m);
        assert(m->socket >= 0);

        if (m->no_delay) {
                r = setsockopt_int(m->socket, IPPROTO_TCP, TCP_NODELAY, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable TCP_NODELAY mode, ignoring: %m");
        }

        if (m->send_buffer > 0) {
                r = fd_set_sndbuf(m->socket, m->send_buffer, false);
                if (r < 0)
                        log_debug_errno(r, "TCP: SO_SNDBUF/SO_SNDBUFFORCE failed: %m");
        }

        if (m->keep_alive) {
                r = setsockopt_int(m->socket, SOL_SOCKET, SO_KEEPALIVE, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to enable SO_KEEPALIVE: %m");
        }

        if (timestamp_is_set(m->keep_alive_time)) {
                r = setsockopt_int(m->socket, SOL_TCP, TCP_KEEPIDLE, m->keep_alive_time / USEC_PER_SEC);
                if (r < 0)
                        log_debug_errno(r, "TCP_KEEPIDLE failed: %m");
        }

        if (m->keep_alive_interval > 0) {
                r = setsockopt_int(m->socket, SOL_TCP, TCP_KEEPINTVL, m->keep_alive_interval / USEC_PER_SEC);
                if (r < 0)
                        log_debug_errno(r, "TCP_KEEPINTVL failed: %m");
        }

        if (m->keep_alive_cnt > 0) {
                r = setsockopt_int(m->socket, SOL_TCP, TCP_KEEPCNT, m->keep_alive_cnt);
                if (r < 0)
                        log_debug_errno(r, "TCP_KEEPCNT failed: %m");
        }

        return 0;
}

int manager_open_network_socket(Manager *m) {
        int r;

        assert(m);

        if (!IN_SET(m->address.sockaddr.sa.sa_family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_UDP:
                        m->socket = socket(m->address.sockaddr.sa.sa_family, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TCP:
                        m->socket = socket(m->address.sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        break;
                default:
                        return -EPROTONOSUPPORT;
        }
        if (m->socket < 0)
                return log_error_errno(errno, "Failed to create socket: %m");

        log_debug("Successfully created socket with fd='%d'", m->socket);

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_UDP: {
                        r = setsockopt_int(m->socket, IPPROTO_IP, IP_MULTICAST_LOOP, true);
                        if (r < 0)
                                log_debug_errno(errno, "UDP: Failed to set IP_MULTICAST_LOOP: %m");

                        if (m->send_buffer > 0) {
                                r = fd_set_sndbuf(m->socket, m->send_buffer, false);
                                if (r < 0)
                                        log_debug_errno(r, "UDP: SO_SNDBUF/SO_SNDBUFFORCE failed: %m");
                        }}

                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TCP: {
                        r = apply_tcp_socket_options(m);
                        if (r < 0)
                                return r;
                }
                        break;
                default:
                        break;
        }

        r = fd_nonblock(m->socket, true);
        if (r < 0)
                log_debug_errno(errno, "Failed to set socket='%d' nonblock: %m", m->socket);

        r = manager_network_connect_socket(m);
        if (r < 0)
                goto fail;

        m->connected = true;
        return 0;

 fail:
        m->socket = safe_close(m->socket);
        return r;
}
