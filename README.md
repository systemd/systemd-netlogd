# systemd-netlogd 🚀

[![Build Status](https://github.com/systemd/systemd-netlogd/actions/workflows/ci.yml/badge.svg)](https://github.com/systemd/systemd-netlogd/actions)

**`systemd-netlogd`** is a **lightweight, battle-tested daemon** that **forwards systemd journal logs to remote hosts** over the network using the **Syslog protocol (RFC 5424 & RFC 3339)**.
It supports **unicast** and **multicast**, with **zero disk buffering** — perfect for **edge devices, servers, and cloud fleets**.

---

## Overview ✨

### Key Features 🔥
| Feature | Description |
|--------|-------------|
| **Network-Aware** | Auto-starts when network is up, pauses when down (`sd-network` integration) |
| **Zero Buffering** | Reads journal **sequentially**, forwards **one-by-one** — no disk, no bloat |
| **Full Protocol Support** | `UDP`, `TCP`, **TLS**, **DTLS** (RFC 6012) |
| **Flexible Formatting** | **RFC 5424** (default), **RFC 3339**, length-prefixed for TLS |
| **Security First** | TLS cert validation, keepalives, sensitive log filtering |
| **Namespace Aware** | Target specific journals or aggregate all |
| **Isolated Execution** | Runs as `systemd-journal-netlog` system user |

> **Ideal for**: Centralized logging without local storage impact

---

## Installation 🛠️

### Prerequisites
Requires **systemd v255+** for full features.

#### Debian / Ubuntu
```bash
sudo apt update
sudo apt install build-essential gperf libcap-dev libsystemd-dev pkg-config meson python3-sphinx
```

#### CentOS / RHEL / Fedora
```bash
sudo dnf group install 'Development Tools'
sudo dnf install gperf libcap-devel pkg-config systemd-devel meson python3-sphinx
```

---

### Build from Source
```bash
git clone https://github.com/systemd/systemd-netlogd.git
cd systemd-netlogd
meson setup build
meson compile -C build
sudo meson install -C build
```

> *Tip*: Prefer `meson`. `make` still works but is legacy.

---

### Create System User (Required)
#### Option 1: Sysusers (Recommended)
```bash
# Copy provided file or create:
sudo tee /etc/sysusers.d/systemd-netlogd.conf > /dev/null <<EOF
u systemd-journal-netlog - - / /bin/nologin
EOF
sudo systemd-sysusers
```

#### Option 2: Manual
```bash
sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog
```

---

### Package Managers
| Distro | Command |
|-------|--------|
| **Ubuntu** (Plucky+, Quokka+, Raccoon+) | `sudo apt install systemd-netlogd` |
| **Fedora** | Search COPR: `systemd-netlogd` |
| **Arch Linux** | AUR: `systemd-netlogd-git` |

---

## Running the Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-netlogd.service
```

Check logs:
```bash
journalctl -u systemd-netlogd.service -f
```

Manual test:
```bash
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd-netlogd
```

---

## Configuration

Config: `/etc/systemd/netlogd.conf`
Drop-ins: `/etc/systemd/netlogd.conf.d/*.conf` (INI format)

Reload: `sudo systemctl reload systemd-netlogd.service`

### `[Network]` Options

| Option | Description | Default | Example |
|-------|-------------|--------|--------|
| `Address=` | Destination (IP:port or multicast) | **Required** | `239.0.0.1:6000` |
| `Protocol=` | `udp` \| `tcp` \| `tls` \| `dtls` | `udp` | `tls` |
| `LogFormat=` | `rfc5424` \| `rfc3339` | `rfc5424` | `rfc3339` |
| `Directory=` | Custom journal path | System default | `/var/log/journal` |
| `Namespace=` | `*`, `+id`, or `id` | Default | `*` |
| `ConnectionRetrySec=` | Retry delay | `30s` | `1min` |
| `TLSCertificateAuthMode=` | `deny` \| `warn` \| `allow` \| `no` | `deny` | `warn` |
| `TLSServerCertificate=` | CA/server PEM path | None | `/etc/ssl/ca.pem` |
| `KeepAlive=` | TCP keepalive | `false` | `true` |
| `NoDelay=` | Disable Nagle (low latency) | `false` | `true` |
| `StructuredData=` | Custom SD-ID | None | `[app@12345]` |
| `UseSysLogStructuredData=` | Extract from journal | `false` | `yes` |
| `UseSysLogMsgId=` | Extract MSGID | `false` | `yes` |
| `ExcludeSyslogFacility=` | Skip facilities | None | `auth authpriv` |
| `ExcludeSyslogLevel=` | Skip levels | None | `debug info` |

---

## Configuration Examples

### 1. UDP Multicast
```ini
[Network]
Address=239.0.0.1:6000
# Protocol=udp (default)
```

### 2. Unicast + RFC 3339
```ini
[Network]
Address=192.168.1.100:514
LogFormat=rfc3339
```

### 3. Cloud-Ready RFC 5424
```ini
[Network]
Address=logs.papertrailapp.com:12345
LogFormat=rfc5424
StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]
```

### 4. Extract Journal Metadata
```ini
[Network]
Address=192.168.1.100:514
LogFormat=rfc5424
UseSysLogStructuredData=yes
UseSysLogMsgId=yes
```

### 5. Filter Sensitive Logs
```ini
[Network]
Address=192.168.1.100:514
ExcludeSyslogFacility=auth authpriv
ExcludeSyslogLevel=debug
```

### 6. Secure TLS (Recommended)
```ini
[Network]
Address=secure-logger.example.com:6514
Protocol=tls
LogFormat=rfc5424
TLSCertificateAuthMode=deny
TLSServerCertificate=/etc/ssl/ca-bundle.pem
KeepAlive=true
NoDelay=true
```

### 7. DTLS (UDP + Encryption)
```ini
[Network]
Address=192.168.1.100:4433
Protocol=dtls
TLSCertificateAuthMode=allow
```

---

## Tag Journal Entries (C Example)

```c
#include <systemd/sd-journal.h>

int main() {
    sd_journal_send(
        "MESSAGE=Login attempt",
        "PRIORITY=4",
        "SYSLOG_FACILITY=10",  // authpriv
        "SYSLOG_MSGID=LOGIN001",
        "SYSLOG_STRUCTURED_DATA=[auth@12345 user=\"alice\" ip=\"1.2.3.4\" result=\"success\"]",
        NULL
    );
    return 0;
}
```

Compile:
```bash
gcc tag.c -lsystemd -o tag && ./tag
```

---

## Security Best Practices

| Action | Why |
|------|-----|
| **Use TLS/DTLS** | Encrypt logs in transit |
| **Set `TLSCertificateAuthMode=deny`** | Reject invalid certs |
| **Filter `authpriv`, `auth`** | Prevent credential leaks |
| **Restrict multicast** | Only trusted networks |
| **Audit service** | `systemd-analyze security systemd-netlogd.service` |

---

## Troubleshooting

| Issue | Fix |
|------|-----|
| No logs forwarded | `journalctl -u systemd-netlogd` |
| Connection refused | Check firewall, `ConnectionRetrySec` |
| TLS errors | `openssl s_client -connect host:port` |
| Test receiver | `nc -ul 514` |
| Generate test log | `logger -p user.info "Hello from netlogd!"` |
| Debug mode | Add override: `StandardOutput=journal+console` |

---

## Contributing

We welcome contributions! Please see our comprehensive contribution guide:

📖 **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development setup, coding standards, and PR guidelines

Quick start:
1. Fork the repository
2. Create your feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## Documentation

Comprehensive documentation is available:

| Document | Description |
|----------|-------------|
| **[README.md](README.md)** | This file - Quick start and configuration guide |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Internal architecture and design decisions |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Development setup and contribution guidelines |
| **[TESTING.md](TESTING.md)** | Testing guide with examples |
| **[FAQ.md](FAQ.md)** | Frequently asked questions |
| **[examples/](examples/)** | Sample configuration files for common scenarios |

---

## Configuration Examples

See the [examples/](examples/) directory for ready-to-use configurations:

- **[basic-udp.conf](examples/basic-udp.conf)** - Simple UDP multicast
- **[basic-tcp.conf](examples/basic-tcp.conf)** - Reliable TCP delivery
- **[tls-secure.conf](examples/tls-secure.conf)** - Encrypted TLS with certificate validation
- **[dtls-encrypted.conf](examples/dtls-encrypted.conf)** - Encrypted DTLS datagrams
- **[cloud-papertrail.conf](examples/cloud-papertrail.conf)** - Papertrail cloud service
- **[cloud-loggly.conf](examples/cloud-loggly.conf)** - Loggly cloud service
- **[filtering.conf](examples/filtering.conf)** - Filter sensitive logs
- **[structured-data.conf](examples/structured-data.conf)** - Use structured data
- **[high-performance.conf](examples/high-performance.conf)** - Optimized for high volume
- **[development.conf](examples/development.conf)** - Development/testing setup

---

## License

**LGPL-2.1-or-later** — same as systemd.
See `LICENSE`.

---

## Getting Help

- 📖 **[FAQ](FAQ.md)** - Frequently asked questions
- 🐛 **[Issues](https://github.com/systemd/systemd-netlogd/issues)** - Report bugs or request features
- 💬 **[Discussions](https://github.com/systemd/systemd-netlogd/discussions)** - Community Q&A
- 📚 **[Documentation](ARCHITECTURE.md)** - Deep dive into internals

> **Star this repo if you find it useful!**
