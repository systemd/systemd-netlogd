Name:           systemd-netlogd
Version:        1.2
Release:        1%{?dist}
Summary:        Forwards messages from the journal to other hosts over the network using syslog format RFC 5424

License:        GPLv2 and LGPL-2.1+ and CC0
URL:            https://github.com/systemd/systemd-netlogd
Source0:        %{URL}/archive/v%{version}.tar.gz

BuildRequires:  gperf
BuildRequires:  libcap-devel
BuildRequires:  pkg-config
BuildRequires:  systemd-devel
BuildRequires:  python3-sphinx
BuildRequires:  meson >= 0.43

%description
Forwards messages from the journal to other hosts over the network using
the Syslog Protocol (RFC 5424). It can be configured to send messages to
both unicast and multicast addresses. systemd-netlogd runs with own user
systemd-journal-netlog. Starts sending logs when network is up and stops
sending as soon as network is down (uses sd-network).

BuildRequires:  gcc
BuildRequires:  libcap-devel
BuildRequires:  docbook-style-xsl
BuildRequires:  gperf
BuildRequires:  python3-devel
BuildRequires:  python3-lxml
BuildRequires:  git
BuildRequires:  meson >= 0.43
BuildRequires:  systemd-devel

%prep
%autosetup
rm -rf build && mkdir build

%build
pushd build
  meson ..
  ninja-build -v
popd

%install
pushd build
  DESTDIR=%{buildroot} ninja-build -v install
popd

%files
%{_sysconfdir}/systemd/system/systemd-netlogd.conf
%{_sysconfdir}/systemd/system/systemd-netlogd.service
/lib/systemd/systemd-netlogd
%{_mandir}/man1/systemd-netlogd.1*

%changelog
* Mon May 21 2018 Susant Sahani <ssahani@gmail.com> - 1.1
- Initial spec
