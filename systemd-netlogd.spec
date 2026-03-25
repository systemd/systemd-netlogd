Name:           systemd-netlogd
Version:        1.4.5
Release:        1%{?dist}
Summary:        Forwards messages from the journal to other hosts over the network using syslog format RFC 5424

License:        LGPL-2.1-or-later AND GPL-2.0-only
URL:            https://github.com/systemd/systemd-netlogd
Source0:        %{URL}/archive/v%{version}/systemd-netlogd-%{version}.tar.gz

%global debug_package %{nil}

BuildRequires:  gcc
BuildRequires:  meson >= 0.51
BuildRequires:  ninja-build
BuildRequires:  gperf
BuildRequires:  libcap-devel
BuildRequires:  systemd-devel >= 230
BuildRequires:  openssl-devel
BuildRequires:  python3-sphinx
BuildRequires:  python3-devel
BuildRequires:  python3-lxml
BuildRequires:  libcmocka-devel

Requires:       systemd >= 230
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Forwards messages from the journal to other hosts over the network
using the Syslog Protocol (RFC 5424 and RFC 3164). It can be configured
to send messages to both unicast and multicast addresses.

systemd-netlogd runs with its own user systemd-journal-netlog. It starts
sending logs when network is up and stops sending as soon as network is
down (uses sd-network). It reads from journal and forwards to network
sequentially without local buffering or disk usage.

Supported transports: UDP, TCP, TLS (RFC 5425), DTLS (RFC 6012)

%prep
%autosetup

%build
meson setup redhat-linux-build \
  --prefix=/usr/lib/systemd \
  --sysconfdir=/etc/systemd \
  --buildtype=plain
ninja -C redhat-linux-build %{?_smp_mflags}

%check
ninja -C redhat-linux-build test

%install
DESTDIR=%{buildroot} ninja -C redhat-linux-build install
mkdir -p %{buildroot}/var/lib/systemd-netlogd

%pre
getent group systemd-journal >/dev/null 2>&1 || groupadd -r systemd-journal 2>/dev/null || :
getent passwd systemd-journal-netlog >/dev/null || \
    useradd -r -g systemd-journal -d / -s /sbin/nologin \
    -c "systemd Network Logging" systemd-journal-netlog 2>/dev/null || :

%post
%systemd_post systemd-netlogd.service

%preun
%systemd_preun systemd-netlogd.service

%postun
%systemd_postun_with_restart systemd-netlogd.service

%files
%license LICENSE.LGPL2.1 LICENSE.GPL2
%doc README.md CONTRIBUTING.md ARCHITECTURE.md TESTING.md FAQ.md CHANGELOG.md SECURITY.md
%doc examples/
%config(noreplace) %{_sysconfdir}/systemd/netlogd.conf
%{_prefix}/lib/systemd/systemd-netlogd
%{_unitdir}/systemd-netlogd.service
%{_mandir}/man8/systemd-netlogd.8*
%dir %attr(0755,systemd-journal-netlog,systemd-journal) /var/lib/systemd-netlogd

%changelog
* Mon Jan 20 2025 Susant Sahani <ssahani@gmail.com> - 1.4.5-1
- Update to version 1.4.5
- Add comprehensive test suite with cmocka
- Add GitHub Actions CI integration
- Add extensive documentation (CONTRIBUTING.md, ARCHITECTURE.md, TESTING.md, FAQ.md)
- Add configuration examples directory
- Enhance man page with security and performance sections
- Modernize README with Quick Start and troubleshooting
- Fix spec file: remove duplicate BuildRequires, add user creation, use systemd macros
- Add %check section to run tests during build
- Include documentation and examples in package

* Tue May 14 2024 Susant Sahani <ssahani@gmail.com> - 1.4-1
- Initial spec
