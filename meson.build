project('systemd-netlogd', 'c',
        version : '1.4.1',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr/lib/systemd',
                'sysconfdir=/etc/systemd',
                'localstatedir=/var',
                'warning_level=2',
        ],
        meson_version : '>= 0.51')

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_STRING',  meson.project_name() + ' ' + meson.project_version())

substs = configuration_data()
substs.set('PACKAGE_URL',          'https://github.com/systemd/systemd-netlogd')
substs.set('PACKAGE_VERSION',      meson.project_version())
substs.set('PKGPREFIX',   get_option('prefix'))
conf.set_quoted('PKGSYSCONFDIR',   get_option('sysconfdir'))

#####################################################################

cc = meson.get_compiler('c')

c_args = '''
        -Wextra
        -Werror=undef
        -Werror=format=2
        -Wformat-security
        -Wformat-nonliteral
        -Wlogical-op
        -Wmissing-include-dirs
        -Werror=old-style-definition
        -Werror=pointer-arith
        -Winit-self
        -Wdeclaration-after-statement
        -Wfloat-equal
        -Wsuggest-attribute=noreturn
        -Werror=missing-prototypes
        -Werror=implicit-function-declaration
        -Werror=missing-declarations
        -Werror=return-type
        -Werror=incompatible-pointer-types
        -Werror=shadow
        -Wstrict-prototypes
        -Wredundant-decls
        -Wmissing-noreturn
        -Wendif-labels
        -Wstrict-aliasing=2
        -Wwrite-strings
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-result
        -Werror=overflow
        -Werror=sign-compare
        -Wdate-time
        -Wnested-externs
        -ffast-math
        -fno-common
        -fdiagnostics-show-option
        -fno-strict-aliasing
        -fvisibility=hidden
        -fstack-protector
        -fstack-protector-strong
        -fPIE
        --param=ssp-buffer-size=4
'''.split()

foreach arg : c_args
        if cc.has_argument(arg)
                add_project_arguments(arg, language : 'c')
        endif
endforeach

conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
conf.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))

foreach ident : [
        ['gettid',            '''#include <sys/types.h>
                                 #include <unistd.h>'''],
]
        have = cc.has_function(ident[0], prefix : ident[1])
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

if cc.has_function('getrandom', prefix : '''#include <sys/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', true)
        conf.set10('HAVE_GETRANDOM', true)
else
        have = cc.has_function('getrandom', prefix : '''#include <linux/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', false)
        conf.set10('HAVE_GETRANDOM', have)
endif

############################################################
gperf = find_program('gperf')

gperf_test_format = '''
#include <string.h>
const char * in_word_set(const char *, @0@);
@1@
'''
gperf_snippet_format = 'echo foo,bar | @0@ -L ANSI-C'
gperf_snippet = run_command('sh', '-c', gperf_snippet_format.format(gperf.path()))
gperf_test = gperf_test_format.format('size_t', gperf_snippet.stdout())
if cc.compiles(gperf_test)
        gperf_len_type = 'size_t'
else
        gperf_test = gperf_test_format.format('unsigned', gperf_snippet.stdout())
        if cc.compiles(gperf_test)
                gperf_len_type = 'unsigned'
        else
                error('unable to determine gperf len type')
        endif
endif
message('gperf len type is @0@'.format(gperf_len_type))
conf.set('GPERF_LEN_TYPE', gperf_len_type,
         description : 'The type of gperf "len" parameter')

############################################################

libopenssl = dependency('openssl',
                        version : '>= 1.1.0',
                        required : get_option('openssl'))
conf.set10('HAVE_OPENSSL', libopenssl.found())

############################################################
config_h = configure_file(
        output : 'config.h',
        configuration : conf)
add_project_arguments('-include', 'config.h', language : 'c')

subdir('src')
includes = include_directories('src/share',
                               'src/netlog')

subdir('units')
subdir('doc')

############################################################

libsystemd = dependency('libsystemd',
                     version : '>= 230')

libcap = dependency('libcap', required : false)
if not libcap.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        libcap = cc.find_library('cap')
endif

systemd_netlogd_conf = configure_file(
                     input : 'conf/netlogd.conf.in',
                     output : 'netlogd.conf',
                     configuration : substs)
                     install_data(systemd_netlogd_conf,
                     install_dir : get_option('sysconfdir'))

systemd_netlogd = executable(
                  'systemd-netlogd',
                   systemd_netlogd_sources,
                   include_directories : includes,
                   link_with : libshared,
                   dependencies : [
                   libcap,
                   libopenssl,
                   libsystemd],
                   install : true,
                   install_dir : get_option('prefix'))
