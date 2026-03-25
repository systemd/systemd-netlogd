all: build
	ninja -C build
.PHONY: all

build:
	meson setup build
.PHONY: build

clean:
	rm -rf build/
.PHONY: clean

install: all
	ninja -C build install
.PHONY: install

uninstall:
	ninja -C build uninstall
.PHONY: uninstall

test: all
	meson test -C build -v
.PHONY: test

install-tree: all
	rm -rf build/install-tree
	DESTDIR=install-tree ninja -C build install
	tree build/install-tree
.PHONY: install-tree

rpm: all
	rpmbuild -ba systemd-netlogd.spec
.PHONY: rpm
