# systemd-netlogd

[![Build Status](https://github.com/systemd/systemd-netlogd/actions/workflows/ci.yml/badge.svg)](https://github.com/systemd/systemd-netlogd/actions)
[![License: LGPL v2.1+](https://img.shields.io/badge/License-LGPL%20v2.1+-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)

Forwards messages from the systemd journal to remote hosts over the
network using the Syslog protocol (RFC 5424 and RFC 3164). Supports
unicast and multicast destinations with UDP, TCP, TLS (RFC 5425), and
DTLS (RFC 6012) transports.

systemd-netlogd reads from the journal and forwards to the network
sequentially — no local buffering or extra disk usage. It starts
sending logs when the network is up and stops when it goes down
(using `sd-network`), and runs as the unprivileged
`systemd-journal-netlog` user.

## Features

- **Network-aware** — automatically detects network state changes via `sd-network`
- **Zero buffering** — sequential journal reading without local caching
- **Secure transports** — UDP, TCP, TLS (RFC 5425), DTLS (RFC 6012)
- **Standard formats** — RFC 5424 (recommended), RFC 3164 (legacy BSD syslog)
- **Smart filtering** — exclude sensitive facilities (auth/authpriv) and log levels
- **Namespace support** — forward from specific journal namespaces or aggregate all
- **Hardened** — runs as unprivileged user with restricted capabilities
- **Fault tolerant** — automatic reconnection with cursor persistence ensures no message loss

## Quick Start

```bash
# Configure
sudo tee /etc/systemd/netlogd.conf <<EOF
[Network]
Address=logs.example.com:514
Protocol=tcp
EOF

# Create system user
sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog

# Start
sudo systemctl enable --now systemd-netlogd
```

View status:
```bash
journalctl -u systemd-netlogd -f
```

## Installation

### Package Manager

| Distribution   | Command                             |
|----------------|-------------------------------------|
| Ubuntu/Debian  | `sudo apt install systemd-netlogd`  |
| Fedora         | Available via COPR repositories     |
| Arch Linux     | AUR: `yay -S systemd-netlogd-git`  |

### Build from Source

**Prerequisites:** systemd >= 230 (v255+ recommended), meson, gperf, libcap, OpenSSL

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential meson gperf libcap-dev libsystemd-dev libssl-dev libcmocka-dev

# Install dependencies (Fedora/RHEL)
sudo dnf install gcc meson gperf libcap-devel systemd-devel openssl-devel libcmocka-devel

# Build
git clone https://github.com/systemd/systemd-netlogd.git
cd systemd-netlogd
meson setup build
meson compile -C build

# Run tests
meson test -C build

# Install
sudo meson install -C build

# Create system user and start
sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-netlogd
```

## Configuration

Configuration file: `/etc/systemd/netlogd.conf`

Drop-in overrides: `/etc/systemd/netlogd.conf.d/*.conf`

Reload after changes: `sudo systemctl reload systemd-netlogd`

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `Address=` | Destination (IP:port or multicast group) | **Required** |
| `Protocol=` | `udp`, `tcp`, `tls`, `dtls` | `udp` |
| `LogFormat=` | `rfc5424`, `rfc5425` (TLS), `rfc3164` (legacy) | `rfc5424` |
| `Directory=` | Custom journal directory path | System default |
| `Namespace=` | Journal namespace: `*` (all), `+id` (id+default), `id` | Default |
| `ConnectionRetrySec=` | Reconnect delay after failure | `30s` |
| `TLSCertificateAuthMode=` | Certificate validation: `deny`, `warn`, `allow`, `no` | `deny` |
| `TLSServerCertificate=` | CA/server certificate PEM path | System CA store |
| `KeepAlive=` | Enable TCP keepalive probes | `false` |
| `KeepAliveTimeSec=` | Keepalive idle timeout | `7200` |
| `KeepAliveIntervalSec=` | Keepalive probe interval | `75` |
| `KeepAliveProbes=` | Keepalive probe count | `9` |
| `SendBuffer=` | Socket send buffer size (bytes, K, M, G) | System default |
| `NoDelay=` | Disable Nagle's algorithm (lower latency) | `false` |
| `StructuredData=` | Static structured data `[SD-ID@PEN ...]` | None |
| `UseSysLogStructuredData=` | Extract `SYSLOG_STRUCTURED_DATA` from journal | `false` |
| `UseSysLogMsgId=` | Extract `SYSLOG_MSGID` from journal | `false` |
| `ExcludeSyslogFacility=` | Space-separated facility list to exclude | None |
| `ExcludeSyslogLevel=` | Space-separated level list to exclude | None |

**Facilities:** `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `ntp`, `security`, `console`, `solaris-cron`, `local0`–`local7`

**Levels:** `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`

### Examples

**Basic UDP:**
```ini
[Network]
Address=192.168.1.100:514
```

**Production TLS (recommended):**
```ini
[Network]
Address=logs.example.com:6514
Protocol=tls
LogFormat=rfc5425
TLSCertificateAuthMode=deny
TLSServerCertificate=/etc/pki/tls/certs/ca-bundle.crt
KeepAlive=yes
NoDelay=yes
ExcludeSyslogFacility=auth authpriv
```

**Cloud service (Papertrail):**
```ini
[Network]
Address=logs7.papertrailapp.com:12345
Protocol=tls
```

**With structured data:**
```ini
[Network]
Address=192.168.1.100:514
Protocol=tcp
LogFormat=rfc5424
StructuredData=[app@12345 env="production" region="us-east"]
UseSysLogStructuredData=yes
UseSysLogMsgId=yes
```

See the [`examples/`](examples/) directory for more production-ready configurations.

## Troubleshooting

```bash
# Check service status
sudo systemctl status systemd-netlogd
journalctl -u systemd-netlogd -n 50

# Test network connectivity
nc -vz remote-server 514    # TCP
nc -u -vz remote-server 514 # UDP

# Generate test log
logger -p user.info "Test from systemd-netlogd"

# Enable debug logging temporarily
sudo kill -SIGUSR1 $(pidof systemd-netlogd)

# Or persistently via systemd override
sudo systemctl edit systemd-netlogd
# Add: Environment=SYSTEMD_LOG_LEVEL=debug

# Test TLS connectivity
openssl s_client -connect server:6514 -CAfile /path/to/ca.pem

# Reset state (re-forward from current journal position)
sudo systemctl stop systemd-netlogd
sudo rm /var/lib/systemd-netlogd/state
sudo systemctl start systemd-netlogd
```

## Documentation

- **[Man page](doc/index.rst)** — full reference (`man systemd-netlogd`)
- **[FAQ](FAQ.md)** — common questions and answers
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — internal design and data flow
- **[TESTING.md](TESTING.md)** — test suite and validation guide
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — development setup and contribution guide
- **[SECURITY.md](SECURITY.md)** — security policy and vulnerability reporting
- **[CHANGELOG.md](CHANGELOG.md)** — release history
- **[examples/](examples/)** — production-ready configuration examples

## Contributing

```bash
git clone https://github.com/systemd/systemd-netlogd.git
cd systemd-netlogd
meson setup build
meson compile -C build
meson test -C build -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

LGPL-2.1-or-later — same license as systemd. See [LICENSE.LGPL2.1](LICENSE.LGPL2.1).

## Author

Susant Sahani <ssahani@gmail.com>
