/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>

#include "build.h"
#include "capability-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "netlog-conf.h"
#include "netlog-manager.h"
#include "network-util.h"
#include "path-util.h"
#include "user-util.h"
#include "util.h"

#define STATE_FILE "/var/lib/systemd/journal-netlogd/state"

static const char *arg_cursor = NULL;
static const char *arg_save_state = STATE_FILE;

static int setup_cursor_state_file(Manager *m, uid_t uid, gid_t gid) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(m);

        r = mkdir_parents(m->state_file, 0755);
        if (r < 0)
                return log_error_errno(r, "Cannot create parent directory of state file %s: %m",
                                       m->state_file);

        /* change permission of the state file parent dir */
        r = chmod_and_chown("/var/lib/systemd/journal-netlogd", 0744, uid, gid);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to change permission parent directory of state file %s: %m",
                                       m->state_file);

        fd = open(m->state_file, O_RDWR|O_CLOEXEC, 0644);
        if (fd >= 0) {

                /* Try to fix the access mode, so that we can still
                   touch the file after dropping privileges */
                fchmod(fd, 0644);
                fchown(fd, uid, gid);
        } else
                /* create stamp file with the compiled-in date */
                return touch_file(m->state_file, true, USEC_INFINITY, uid, gid, 0644);

        return 0;
}

static void help(void) {
        printf("%s ..\n\n"
               "Forwards messages from the journal to other hosts over the network using the syslog\n"
               "RFC 5424 or RFC3339 format in both unicast and multicast addresses.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --cursor=CURSOR        Start at the specified cursor\n"
               "     --save-state[=FILE]    Save uploaded cursors (default \n"
               "                            " STATE_FILE ")\n"
               "  -h --help                 Show this help and exit\n"
               "     --version              Print version string and exit\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_CURSOR,
                ARG_SAVE_STATE,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'                },
                { "version",      no_argument,       NULL, ARG_VERSION        },
                { "cursor",       required_argument, NULL, ARG_CURSOR         },
                { "save-state",   optional_argument, NULL, ARG_SAVE_STATE     },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_CURSOR:
                        if (arg_cursor) {
                                log_error("cannot use more than one --cursor/--after-cursor");
                                return -EINVAL;
                        }

                        arg_cursor = optarg;
                        break;
                case ARG_SAVE_STATE:
                        arg_save_state = optarg ?: STATE_FILE;
                        break;

                case '?':
                        log_error("Unknown option %s.", argv[optind-1]);
                        return -EINVAL;

                case ':':
                        log_error("Missing argument to %s.", argv[optind-1]);
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }


        if (optind < argc) {
                log_error("Input arguments make no sense with journal input.");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char **argv) {
        _cleanup_(manager_freep) Manager *m = NULL;
        const char *user = "systemd-journal-netlog";
        uid_t uid;
        gid_t gid;
        int r;

        log_show_color(true);
        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        umask(0022);

        r = get_user_creds(&user, &uid, &gid, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Cannot resolve user name %s: %m", user);
                goto finish;
        }

        r = manager_new(arg_save_state, arg_cursor, &m);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate manager: %m");
                goto finish;
        }

        r = manager_parse_config_file(m);
        if (r < 0) {
                log_error_errno(r, "Failed to parse configuration file: %m");
                goto finish;
        }

        switch (m->protocol) {
                case SYSLOG_TRANSMISSION_PROTOCOL_DTLS:
                        r = dtls_manager_init(&m->dtls);
                        break;
                case SYSLOG_TRANSMISSION_PROTOCOL_TLS:
                        r = tls_manager_init(&m->tls);
                        break;
                default:
                        break;
        }

        if (r < 0)
                return r;

        r = setup_cursor_state_file(m, uid, gid);
        if (r < 0)
                goto cleanup;

        r = drop_privileges(uid, gid,
                            (1ULL << CAP_NET_ADMIN) |
                            (1ULL << CAP_NET_BIND_SERVICE) |
                            (1ULL << CAP_NET_BROADCAST));
        if (r < 0)
                goto finish;

        log_debug("%s running as pid "PID_FMT,
                  program_invocation_short_name, getpid());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing input...");

        if (network_is_online())
               manager_connect(m);

        r = sd_event_loop(m->event);
        if (r < 0) {
                log_error_errno(r, "Failed to run event loop: %m");
                goto finish;
        }

        sd_event_get_exit_code(m->event, &r);

 cleanup:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

 finish:
        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
