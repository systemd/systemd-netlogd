#  -*- Mode: makefile; indent-tabs-mode: t -*-
#
#  This file is part of systemd-netlogd
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

GCC_COLORS ?= 'ooh, shiny!'
export GCC_COLORS

SUBDIRS = .

# remove targets if the command fails
.DELETE_ON_ERROR:

# keep intermediate files
.SECONDARY:

# Keep the test-suite.log
.PRECIOUS: $(TEST_SUITE_LOG) Makefile

# Dirs of external packages
systemdir=@systemdir@

# And these are the special ones for /
rootprefix=@rootprefix@
rootbindir=$(rootprefix)/bin
rootlibexecdir=$(rootprefix)/lib/systemd
pkgsysconfdir=$(sysconfdir)/systemd
systemunitdir=$(rootprefix)/lib/systemd/system

AM_CFLAGS = $(OUR_CFLAGS)
AM_LDFLAGS = $(OUR_LDFLAGS)
AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DPKGSYSCONFDIR=\"$(pkgsysconfdir)\" \
	-DSYSTEM_CONFIG_UNIT_PATH=\"$(pkgsysconfdir)/system\" \
	-DSYSTEM_DATA_UNIT_PATH=\"$(systemunitdir)\" \
	-DSYSTEMD_BINARY_PATH=\"$(rootlibexecdir)/systemd\" \
	-DROOTPREFIX=\"$(rootprefix)\" \
	-DLIBDIR=\"$(libdir)\" \
	-DROOTLIBDIR=\"$(rootlibdir)\" \
	-DROOTLIBEXECDIR=\"$(rootlibexecdir)\" \
	-DCATALOG_DATABASE=\"$(catalogstatedir)/database\" \
	-I $(top_srcdir)/src

#####################################################

dist_noinst_DATA = \
	LICENSE.LGPL2.1 \
	LICENSE.GPL2

EXTRA_DIST = \
	man/systemd-netlogd.conf.xml \
	man/custom-man.xsl \
	man/standard-conf.xml \
	man/standard-options.xml \
	units/systemd-netlogd.service.in \
	src/systemd-netlogd.conf.in

MANPAGES = man/systemd-netlogd.conf.5
MANPAGES_ALIAS = man/systemd-netlogd.conf.d.5

man_MANS = $(MANPAGES) $(MANPAGES_ALIAS)

man/systemd-netlogd.conf.d.5: man/systemd-netlogd.conf.5

XSLTPROC_FLAGS = \
	--nonet \
	--xinclude \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0 \
	--stringparam systemd.version $(VERSION) \
	--path '$(builddir)/man:$(srcdir)/man'

XSLT = $(if $(XSLTPROC), $(XSLTPROC), xsltproc)
XSLTPROC_PROCESS_MAN = \
	$(AM_V_XSLT)$(XSLT) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-man.xsl $<

man/%.1: man/%.xml man/custom-man.xsl
	$(XSLTPROC_PROCESS_MAN)

man/%.5: man/%.xml man/custom-man.xsl
	$(XSLTPROC_PROCESS_MAN)

#------------------------------------------------------------------------------

libutils_la_SOURCES = \
	src/missing_syscall.h \
	src/missing.h \
	src/def.h \
	src/capability-util.c \
	src/capability-util.h \
	src/conf-parser.c \
	src/conf-parser.h \
	src/conf-files.c \
	src/conf-files.h \
	src/alloc-util.c \
	src/alloc-util.h \
	src/build.h \
	src/umask-util.h \
	src/set.h \
	src/hashmap.c \
	src/hashmap.h \
	src/siphash24.c \
	src/siphash24.h \
	src/utf8.c \
	src/utf8.h \
	src/strv.c \
	src/strv.h \
	src/network-util.c \
	src/network-util.h \
	src/in-addr-util.c \
	src/in-addr-util.h \
	src/extract-word.c \
	src/extract-word.h \
	src/util.c \
	src/util.h \
	src/log.c \
	src/log.h \
	src/macro.h \
	src/signal-util.c \
	src/signal-util.h \
	src/syslog-util.c \
	src/syslog-util.h \
	src/time-util.c \
	src/time-util.h \
	src/ioprio.h \
	src/io-util.c \
	src/io-util.h \
	src/escape.c \
	src/escape.h \
	src/user-util.c \
	src/user-util.h \
	src/process-util.c \
	src/process-util.h \
	src/terminal-util.c \
	src/terminal-util.h \
	src/proc-cmdline.c \
	src/proc-cmdline.h \
	src/socket-util.c \
	src/socket-util.h \
	src/dirent-util.c \
	src/dirent-util.h \
	src/fd-util.c \
	src/fd-util.h \
	src/sparse-endian.h \
	src/fileio.c \
	src/fileio.h \
	src/formats-util.h \
	src/hash-funcs.c \
	src/hash-funcs.h \
	src/hexdecoct.c \
	src/hexdecoct.h \
	src/list.h \
	src/mempool.c \
	src/mempool.h \
	src/parse-util.c \
	src/parse-util.h \
	src/path-util.c \
	src/path-util.h \
	src/random-util.c \
	src/random-util.h \
	src/stdio-util.h \
	src/string-table.c \
	src/string-table.h \
	src/string-util.c \
	src/string-util.h \
	src/unaligned.h \
	src/stat-util.c \
	src/stat-util.h \
	src/fs-util.c \
	src/fs-util.h \
	src/mkdir.c \
	src/mkdir.h \
	src/virt.c \
	src/virt.h \
	src/sd-network.h \
	src/sd-network.c

libutils_la_CFLAGS = \
        $(AM_CFLAGS) \
        $(CAP_CFLAGS) \
        -pthread

libutils_la_LIBADD = \
        $(CAP_LIBS) \
        -lrt \
        -lm \
	-lsystemd

if HAVE_XZ
libutils_la_CFLAGS += \
        $(XZ_CFLAGS)
libutils_la_LIBADD += \
        $(XZ_LIBS)
endif

noinst_LTLIBRARIES = libutils.la

#-------------------------------------------------------------

systemd_netlogd_SOURCES = \
	src/systemd-netlogd.c \
	src/netlog-conf.h \
	src/netlog-conf.c \
	src/netlog-manager.c \
	src/netlog-manager.h \
	src/netlog-network.c

systemd_netlogd_LDADD = \
	$(CAP_LIBS) \
	libutils.la

nodist_systemd_netlogd_SOURCES = \
	src/netlog-gperf.c

EXTRA_DIST += \
        src/netlog-gperf.gperf

CLEANFILES = \
        src/netlog-gperf.c

#--------------------------------

substitutions = \
	'|rootlibexecdir=$(rootlibexecdir)|'

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED) $(subst '|,-e 's|@,$(subst =,\@|,$(subst |',|g',$(substitutions)))) \
		< $< > $@

units/%: units/%.in
	$(SED_PROCESS)

src/%: src/%.in
	$(SED_PROCESS)

man/%: man/%.in
	$(SED_PROCESS)

src/%.c: src/%.gperf
	$(AM_V_at)$(MKDIR_P) $(dir $@)
	$(AM_V_GPERF)$(GPERF) < $< > $@

rootlibexec_PROGRAMS = systemd-netlogd
dist_pkgsysconf_DATA = src/systemd-netlogd.conf
nodist_systemunit_DATA = units/systemd-netlogd.service

in_files = $(filter %.in,$(EXTRA_DIST))

CLEANFILES += \
	$(MANPAGES) $(MANPAGES_ALIAS) \
	$(pkgconfigdata_DATA) \
	$(pkgconfiglib_DATA) \
	$(in_files:.in=)

install-exec-hook: $(INSTALL_EXEC_HOOKS)

uninstall-hook: $(UNINSTALL_DATA_HOOKS) $(UNINSTALL_EXEC_HOOKS)

install-data-hook: $(INSTALL_DATA_HOOKS)

.PHONY: git-tag
git-tag:
	git tag -s "v$(VERSION)" -m "systemd $(VERSION)"

.PHONY: git-tar
git-tar:
	git archive --format=tar --prefix=systemd-$(VERSION)/ HEAD | xz > systemd-$(VERSION).tar.xz
