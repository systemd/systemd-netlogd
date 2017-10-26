libshared_sources = files('''
	missing_syscall.h
	missing.h
	def.h
	capability-util.c
	capability-util.h
	conf-parser.c
	conf-parser.h
	conf-files.c
	conf-files.h
	alloc-util.c
	alloc-util.h
	build.h
	umask-util.h
	set.h
	hashmap.c
	hashmap.h
	siphash24.c
	siphash24.h
	utf8.c
	utf8.h
	strv.c
	strv.h
	network-util.c
	network-util.h
	in-addr-util.c
	in-addr-util.h
	extract-word.c
	extract-word.h
	util.c
	util.h
	log.c
	log.h
	macro.h
	signal-util.c
	signal-util.h
	syslog-util.c
	syslog-util.h
	time-util.c
	time-util.h
	ioprio.h
	io-util.c
	io-util.h
	escape.c
	escape.h
	user-util.c
	user-util.h
	process-util.c
	process-util.h
	terminal-util.c
	terminal-util.h
	proc-cmdline.c
	proc-cmdline.h
	socket-util.c
	socket-util.h
	dirent-util.c
	dirent-util.h
	fd-util.c
	fd-util.h
	sparse-endian.h
	fileio.c
	fileio.h
	formats-util.h
	hash-funcs.c
	hash-funcs.h
	hexdecoct.c
	hexdecoct.h
	list.h
	mempool.c
	mempool.h
	parse-util.c
	parse-util.h
	path-util.c
	path-util.h
	random-util.c
	random-util.h
	stdio-util.h
	string-table.c
	string-table.h
	string-util.c
	string-util.h
	unaligned.h
	stat-util.c
	stat-util.h
	fs-util.c
	fs-util.h
	mkdir.c
	mkdir.h
	virt.c
	virt.h
	sd-network.h
	sd-network.c
'''.split())

libshared = static_library(
             'shared',
              libshared_sources)

systemd_netlogd_sources = files('''
        systemd-netlogd.c
        netlog-conf.h
        netlog-conf.c
        netlog-manager.c
        netlog-manager.h
        netlog-network.c
'''.split())

netlogd_gperf_c = custom_target(
        'netlog-gperf.c',
        input : 'netlog-gperf.gperf',
        output : 'netlog-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_netlogd_sources += [netlogd_gperf_c]

systemd_netlogd_conf = configure_file(
                 input : 'systemd-netlogd.conf.in',
                 output : 'systemd-netlogd.conf',
                 configuration : substs)
                 install_data(systemd_netlogd_conf,
                 install_dir : get_option('sysconfdir'))
