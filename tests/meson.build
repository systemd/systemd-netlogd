cmocka = dependency('cmocka', required: false)
test_libsystemd = dependency('libsystemd', version : '>= 230')
test_libopenssl = dependency('openssl', version : '>= 1.1.0', required : false)

test_libcap = dependency('libcap', required : false)
if not test_libcap.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        test_libcap = cc.find_library('cap')
endif

if cmocka.found()
        test_protocol = executable(
                'test-protocol',
                'test-protocol.c',
                '../src/netlog/netlog-protocol.c',
                '../src/netlog/netlog-network.c',
                '../src/netlog/netlog-manager.c',
                '../src/netlog/netlog-ssl-common.c',
                '../src/netlog/netlog-tls.c',
                '../src/netlog/netlog-dtls.c',
                '../src/netlog/netlog-ssl.c',
                include_directories : includes,
                link_with : libshared,
                dependencies : [cmocka, test_libsystemd, test_libopenssl, test_libcap],
        )

        test_string_tables = executable(
                'test-string-tables',
                'test-string-tables.c',
                '../src/netlog/netlog-manager.c',
                '../src/netlog/netlog-network.c',
                '../src/netlog/netlog-ssl-common.c',
                '../src/netlog/netlog-tls.c',
                '../src/netlog/netlog-dtls.c',
                '../src/netlog/netlog-ssl.c',
                '../src/netlog/netlog-protocol.c',
                include_directories : includes,
                link_with : libshared,
                dependencies : [cmocka, test_libsystemd, test_libcap, test_libopenssl],
        )

        test('protocol', test_protocol)
        test('string-tables', test_string_tables)
else
        warning('cmocka not found, tests will not be built')
endif
