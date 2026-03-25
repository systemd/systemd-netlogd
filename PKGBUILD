# Maintainer: Susant Sahani <ssahani@gmail.com>
pkgname=systemd-netlogd
pkgver=1.4.5
pkgrel=1
pkgdesc='Forward systemd journal entries to remote syslog servers'
arch=('x86_64' 'aarch64')
url='https://github.com/systemd/systemd-netlogd'
license=('LGPL-2.1-or-later')
depends=('systemd' 'openssl')
makedepends=('meson' 'gperf' 'libcap' 'python-sphinx' 'cmocka')
backup=('etc/systemd/netlogd.conf')
source=("$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$pkgname-$pkgver"
  meson setup build \
    --prefix=/usr/lib/systemd \
    --sysconfdir=/etc/systemd
  meson compile -C build
}

check() {
  cd "$pkgname-$pkgver"
  meson test -C build
}

package() {
  cd "$pkgname-$pkgver"
  DESTDIR="$pkgdir" meson install -C build

  install -Dm644 LICENSE.LGPL2.1 "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}

post_install() {
  getent group systemd-journal >/dev/null 2>&1 || groupadd -r systemd-journal
  getent passwd systemd-journal-netlog >/dev/null || \
    useradd -r -g systemd-journal -d / -s /usr/bin/nologin \
    -c "systemd Network Logging" systemd-journal-netlog
  systemctl daemon-reload
}

post_upgrade() {
  systemctl daemon-reload
}

post_remove() {
  systemctl daemon-reload
}
