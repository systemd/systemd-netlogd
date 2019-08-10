
libshared_sources = files('''
                  share/missing_syscall.h
                  share/missing.h
                  share/def.h
                  share/capability-util.c
                  share/capability-util.h
                  share/conf-parser.c
                  share/conf-parser.h
                  share/conf-files.c
                  share/conf-files.h
                  share/alloc-util.c
                  share/alloc-util.h
                  share/build.h
                  share/set.h
                  share/hashmap.c
                  share/hashmap.h
                  share/siphash24.c
                  share/siphash24.h
                  share/utf8.c
                  share/utf8.h
                  share/strv.c
                  share/strv.h
                  share/network-util.c
                  share/network-util.h
                  share/in-addr-util.c
                  share/in-addr-util.h
                  share/extract-word.c
                  share/extract-word.h
                  share/util.c
                  share/util.h
                  share/log.c
                  share/log.h
                  share/macro.h
                  share/signal-util.c
                  share/signal-util.h
                  share/syslog-util.c
                  share/syslog-util.h
                  share/time-util.c
                  share/time-util.h
                  share/ioprio.h
                  share/io-util.c
                  share/io-util.h
                  share/escape.c
                  share/escape.h
                  share/user-util.c
                  share/user-util.h
                  share/process-util.c
                  share/process-util.h
                  share/terminal-util.c
                  share/terminal-util.h
                  share/proc-cmdline.c
                  share/proc-cmdline.h
                  share/socket-util.c
                  share/socket-util.h
                  share/dirent-util.c
                  share/dirent-util.h
                  share/fd-util.c
                  share/fd-util.h
                  share/sparse-endian.h
                  share/fileio.c
                  share/fileio.h
                  share/formats-util.h
                  share/hash-funcs.c
                  share/hash-funcs.h
                  share/hexdecoct.c
                  share/hexdecoct.h
                  share/list.h
                  share/mempool.c
                  share/mempool.h
                  share/parse-util.c
                  share/parse-util.h
                  share/path-util.c
                  share/path-util.h
                  share/random-util.c
                  share/random-util.h
                  share/stdio-util.h
                  share/string-table.c
                  share/string-table.h
                  share/string-util.c
                  share/string-util.h
                  share/unaligned.h
                  share/stat-util.c
                  share/stat-util.h
                  share/fs-util.c
                  share/fs-util.h
                  share/mkdir.c
                  share/mkdir.h
                  share/virt.c
                  share/virt.h
                  share/sd-network.h
                  share/sd-network.c
                  '''.split())

libshared = static_library(
'shared',
libshared_sources)

systemd_netlogd_sources = files('''
                        netlog/systemd-netlogd.c
                        netlog/netlog-conf.h
                        netlog/netlog-conf.c
                        netlog/netlog-manager.c
                        netlog/netlog-manager.h
                        netlog/netlog-network.c
                        '''.split())

netlogd_gperf_c = custom_target(
                'netlog-gperf.c',
                input : 'netlog/netlog-gperf.gperf',
                output : 'netlog-gperf.c',
                command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_netlogd_sources += [netlogd_gperf_c]
