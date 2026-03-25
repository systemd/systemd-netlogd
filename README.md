# systemd-netlogd

[![Build Status](https://github.com/systemd/systemd-netlogd/actions/workflows/ci.yml/badge.svg)](https://github.com/systemd/systemd-netlogd/actions)
[![License: LGPL v2.1+](https://img.shields.io/badge/License-LGPL%20v2.1+-blue.svg)](https://www.gnu.org/licenses/lgpl-2.1)
[![Version](https://img.shields.io/badge/version-1.4.5-green.svg)](https://github.com/systemd/systemd-netlogd/releases)

> **Lightweight, network-aware daemon for forwarding systemd journal logs to remote syslog servers**

Forward your systemd journal to centralized logging infrastructure with zero local buffering, automatic network detection, and secure transport options (UDP, TCP, TLS, DTLS).

---

## ⚡ Quick Start

```bash
# Install (Ubuntu/Debian)
sudo apt install systemd-netlogd

# Or build from source
git clone https://github.com/systemd/systemd-netlogd.git
cd systemd-netlogd && make && sudo make install

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

**That's it!** Your logs are now being forwarded. View status with:
```bash
journalctl -u systemd-netlogd -f
```

---

## 🎯 Why systemd-netlogd?

<table>
<tr>
<td width="50%">

### ✅ What You Get
- **Zero disk buffering** - No local storage impact
- **Network-aware** - Auto-start/pause with network
- **Secure by default** - TLS/DTLS encryption support
- **Battle-tested** - Production-ready since 2016
- **Resource efficient** - ~2-5 MB memory, <1% CPU
- **Native integration** - Direct systemd journal access

</td>
<td width="50%">

### ❌ What You Don't Need
- No rsyslog/syslog-ng complexity
- No local log buffering/queuing
- No heavy dependencies
- No manual journal export setup
- No root privileges required
- No configuration headaches

</td>
</tr>
</table>

### 🚀 Key Features

- **🌐 Network-Aware**: Automatically detects network state changes via `sd-network`
- **⚡ Zero Buffering**: Sequential journal reading without local caching
- **🔒 Secure Transport**: UDP, TCP, TLS (RFC 5425), DTLS (RFC 6012)
- **📋 Standard Formats**: RFC 5424 (recommended), RFC 3164 (legacy BSD syslog)
- **🎯 Smart Filtering**: Exclude sensitive facilities (auth/authpriv) and log levels
- **📦 Namespace Support**: Forward from specific namespaces or aggregate all
- **🛡️ Hardened**: Runs as unprivileged `systemd-journal-netlog` user with restricted capabilities
- **🔄 Fault Tolerant**: Automatic reconnection with cursor persistence ensures no message loss

### 💡 Use Cases

```
✓ Centralized logging for distributed systems     ✓ Security monitoring & SIEM integration
✓ Cloud log aggregation (AWS, Azure, GCP)         ✓ Compliance & audit log forwarding
✓ Edge device telemetry collection                ✓ Multi-region log consolidation
✓ Container/Kubernetes cluster logging            ✓ IoT fleet management
```

---

## 📦 Installation

### Package Installation (Recommended)

<table>
<tr>
<td><b>Ubuntu/Debian</b></td>
<td><code>sudo apt install systemd-netlogd</code></td>
</tr>
<tr>
<td><b>Fedora</b></td>
<td>Search COPR repositories</td>
</tr>
<tr>
<td><b>Arch Linux</b></td>
<td>AUR: <code>yay -S systemd-netlogd-git</code></td>
</tr>
</table>

### Build from Source

<details>
<summary><b>Click to expand build instructions</b></summary>

**Prerequisites**: systemd v230+ (v255+ recommended)

**Install dependencies:**
```bash
# Debian/Ubuntu
sudo apt install build-essential meson gperf libcap-dev libsystemd-dev libssl-dev libcmocka-dev

# Fedora/RHEL
sudo dnf install gcc meson gperf libcap-devel systemd-devel openssl-devel libcmocka-devel
```

**Build and install:**
```bash
git clone https://github.com/systemd/systemd-netlogd.git
cd systemd-netlogd
make                    # or: meson setup build && meson compile -C build
sudo make install       # or: sudo meson install -C build
```

**Create system user:**
```bash
sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-netlogd
```

</details>

---

## ⚙️ Configuration

### Quick Configuration

**File:** `/etc/systemd/netlogd.conf` (or `/etc/systemd/netlogd.conf.d/*.conf` for drop-ins)

**Reload:** `sudo systemctl reload systemd-netlogd`

### Common Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| **`Address=`** | Destination server (IP:port or multicast) | *Required* |
| **`Protocol=`** | Transport: `udp`, `tcp`, `tls`, `dtls` | `udp` |
| **`LogFormat=`** | Format: `rfc5424`, `rfc5425`, `rfc3164` | `rfc5424` |
| `ConnectionRetrySec=` | Retry interval on failure | `30s` |
| `TLSCertificateAuthMode=` | TLS validation: `deny`, `warn`, `allow`, `no` | `deny` |
| `TLSServerCertificate=` | Path to CA certificate PEM file | System CA |
| `ExcludeSyslogFacility=` | Filter out facilities (e.g., `auth authpriv`) | None |
| `ExcludeSyslogLevel=` | Filter out levels (e.g., `debug info`) | None |

<details>
<summary><b>📋 View all configuration options</b></summary>

| Option | Description | Default |
|--------|-------------|---------|
| `Address=` | Destination (IP:port or multicast group) | **Required** |
| `Protocol=` | `udp`, `tcp`, `tls`, `dtls` | `udp` |
| `LogFormat=` | `rfc5424`, `rfc5425` (TLS), `rfc3164` (legacy) | `rfc5424` |
| `Directory=` | Custom journal directory path | System default |
| `Namespace=` | Journal namespace: `*` (all), `+id` (id+default), `id` | Default |
| `ConnectionRetrySec=` | Reconnect delay after failure | `30s` |
| `TLSCertificateAuthMode=` | Certificate validation mode | `deny` |
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
| `ExcludeSyslogFacility=` | Space-separated facility list | None |
| `ExcludeSyslogLevel=` | Space-separated level list | None |

**Facilities:** `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `ntp`, `security`, `console`, `solaris-cron`, `local0-7`

**Levels:** `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`

</details>

---

## 📝 Configuration Examples

### Basic UDP
```ini
[Network]
Address=192.168.1.100:514
```

### Production TLS (Recommended)
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

### Cloud Service (Papertrail)
```ini
[Network]
Address=logs7.papertrailapp.com:12345
Protocol=tls
```

### High-Performance Local Network
```ini
[Network]
Address=192.168.1.100:514
Protocol=udp
ExcludeSyslogLevel=debug info
ConnectionRetrySec=5
```

### With Structured Data
```ini
[Network]
Address=192.168.1.100:514
Protocol=tcp
LogFormat=rfc5424
StructuredData=[app@12345 env="production" region="us-east"]
```

**📁 More examples:** See [`examples/`](examples/) directory for 10+ production-ready configurations

---

## 🔧 Advanced Usage

### Tag Journal Entries with Structured Data

<details>
<summary><b>Click to see C example</b></summary>

```c
#include <systemd/sd-journal.h>

int main() {
    sd_journal_send(
        "MESSAGE=User login successful",
        "PRIORITY=6",                    // info
        "SYSLOG_FACILITY=10",           // authpriv
        "SYSLOG_MSGID=LOGIN001",
        "SYSLOG_STRUCTURED_DATA=[auth@12345 user=\"alice\" ip=\"1.2.3.4\"]",
        NULL
    );
    return 0;
}
```

Compile: `gcc example.c -lsystemd -o example && ./example`

Configure netlogd to extract structured data:
```ini
[Network]
Address=192.168.1.100:514
LogFormat=rfc5424
UseSysLogStructuredData=yes
UseSysLogMsgId=yes
```

</details>

### Testing and Validation

```bash
# Start a test receiver
nc -ul 514                    # UDP
nc -l 514                     # TCP

# Generate test logs
logger -p user.info "Test message"
logger -p user.warning "Warning test"

# Monitor systemd-netlogd
journalctl -u systemd-netlogd -f

# Enable debug logging
sudo systemctl edit systemd-netlogd
# Add: Environment=SYSTEMD_LOG_LEVEL=debug

# Test TLS connectivity
openssl s_client -connect server:6514 -CAfile /path/to/ca.pem
```

---

## 🔒 Security

**systemd-netlogd runs with minimal privileges:**
- Dedicated `systemd-journal-netlog` system user (not root)
- Capability restrictions via systemd hardening
- Filesystem isolation and protection

**Best Practices:**

```ini
# ✅ DO: Use TLS for remote logging
Protocol=tls
TLSCertificateAuthMode=deny

# ✅ DO: Filter sensitive logs
ExcludeSyslogFacility=auth authpriv

# ✅ DO: Use strong certificate validation
TLSServerCertificate=/etc/pki/tls/certs/ca-bundle.crt

# ❌ DON'T: Use UDP/TCP over the internet (unencrypted)
# ❌ DON'T: Disable certificate validation in production
```

**Audit security posture:**
```bash
sudo systemd-analyze security systemd-netlogd.service
```

---

## 🐛 Troubleshooting

<details>
<summary><b>❓ No logs being forwarded</b></summary>

1. Check service status:
   ```bash
   sudo systemctl status systemd-netlogd
   journalctl -u systemd-netlogd -n 50
   ```

2. Verify configuration:
   ```bash
   cat /etc/systemd/netlogd.conf
   ```

3. Test network connectivity:
   ```bash
   nc -vz remote-server 514    # TCP
   ping remote-server
   ```

4. Check user exists:
   ```bash
   id systemd-journal-netlog
   ```

</details>

<details>
<summary><b>🔐 TLS connection failures</b></summary>

1. Test TLS manually:
   ```bash
   openssl s_client -connect server:6514 -CAfile /path/to/ca.pem
   ```

2. Check certificate validity:
   ```bash
   openssl x509 -in /path/to/ca.pem -noout -dates
   ```

3. Try relaxed validation (testing only):
   ```ini
   TLSCertificateAuthMode=warn
   ```

4. View SSL errors:
   ```bash
   journalctl -u systemd-netlogd | grep -i ssl
   ```

</details>

<details>
<summary><b>🚫 Connection refused</b></summary>

1. Check firewall on remote server
2. Verify remote syslog server is running:
   ```bash
   sudo netstat -tuln | grep 514
   ```
3. Test with netcat as simple receiver:
   ```bash
   nc -ul 514  # UDP
   nc -l 514   # TCP
   ```

</details>

<details>
<summary><b>⚡ Performance issues / lag</b></summary>

1. Check network latency: `ping remote-server`
2. Use UDP for highest throughput
3. Filter debug messages: `ExcludeSyslogLevel=debug info`
4. Increase send buffer: `SendBuffer=262144`
5. Check dropped packets: `netstat -su | grep drop`

</details>

**💡 Quick fixes:**
```bash
# Generate test log
logger -p user.info "Test from systemd-netlogd"

# Enable debug mode
sudo kill -SIGUSR1 $(pidof systemd-netlogd)

# Reset state (start from scratch)
sudo systemctl stop systemd-netlogd
sudo rm /var/lib/systemd-netlogd/state
sudo systemctl start systemd-netlogd
```

---

## 📚 Documentation

<table>
<tr>
<td width="33%">

### 📖 User Guides
- **[README.md](README.md)** *(this file)*
- **[FAQ.md](FAQ.md)** - Common questions
- **[examples/](examples/)** - 10+ configs
- **[Man Page](doc/index.rst)** - Full reference

</td>
<td width="33%">

### 🔧 Developer Guides
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Internal design
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Dev setup
- **[TESTING.md](TESTING.md)** - Test guide

</td>
<td width="33%">

### 📦 Example Configs
- [Basic UDP/TCP](examples/basic-udp.conf)
- [Production TLS](examples/tls-secure.conf)
- [Cloud Services](examples/cloud-papertrail.conf)
- [High Performance](examples/high-performance.conf)

</td>
</tr>
</table>

---

## 🤝 Contributing

We welcome contributions!

**Quick Start:**
1. 🍴 Fork the repository
2. 🌿 Create feature branch: `git checkout -b feature/amazing-feature`
3. ✅ Add tests for new functionality
4. 💬 Commit with clear messages
5. 📫 Submit a pull request

**Resources:**
- 📖 [CONTRIBUTING.md](CONTRIBUTING.md) - Full contribution guide
- 🏗️ [ARCHITECTURE.md](ARCHITECTURE.md) - Understand the codebase
- 🧪 [TESTING.md](TESTING.md) - Testing guide

**Development:**
```bash
# Clone and setup
git clone https://github.com/systemd/systemd-netlogd.git
cd systemd-netlogd
make

# Run tests
meson test -C build -v

# Build documentation
make -C doc
```

---

## 💬 Getting Help

<table>
<tr>
<td align="center">

### 📖 [FAQ](FAQ.md)
50+ questions answered

</td>
<td align="center">

### 🐛 [Issues](https://github.com/systemd/systemd-netlogd/issues)
Report bugs & request features

</td>
<td align="center">

### 💬 [Discussions](https://github.com/systemd/systemd-netlogd/discussions)
Ask questions & share tips

</td>
<td align="center">

### 📚 [Man Page](doc/index.rst)
Complete reference

</td>
</tr>
</table>

**Before asking for help:**
1. ✅ Check the [FAQ](FAQ.md)
2. ✅ Search [existing issues](https://github.com/systemd/systemd-netlogd/issues)
3. ✅ Try [troubleshooting](#-troubleshooting) steps above
4. ✅ Enable debug logging: `Environment=SYSTEMD_LOG_LEVEL=debug`

---

## 📄 License

**LGPL-2.1-or-later** — Same license as systemd

See [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

- **Author**: [Susant Sahani](https://github.com/ssahani)
- **Contributors**: [See all contributors](https://github.com/systemd/systemd-netlogd/graphs/contributors)
- **Project**: Part of the systemd ecosystem

---

<div align="center">

### ⭐ If you find systemd-netlogd useful, please star the repository!

[![GitHub stars](https://img.shields.io/github/stars/systemd/systemd-netlogd?style=social)](https://github.com/systemd/systemd-netlogd/stargazers)

**[Documentation](ARCHITECTURE.md)** • **[Examples](examples/)** • **[FAQ](FAQ.md)** • **[Contributing](CONTRIBUTING.md)**

</div>
