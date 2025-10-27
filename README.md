# systemd-netlogd

[![Build Status](https://github.com/systemd/systemd-netlogd/actions/workflows/ci.yml/badge.svg)](https://github.com/systemd/systemd-netlogd/actions)

**systemd-netlogd** is a lightweight daemon that forwards log messages from the systemd journal to remote hosts over the network using the Syslog protocol (RFC 5424 and RFC 3339). It supports both unicast and multicast destinations, ensuring reliable log aggregation in distributed environments.

## Overview

### Key Features
- **Network-Aware Operation**: Automatically starts forwarding logs when the network is available and pauses when it's down (integrates with `sd-network`).
- **Efficient Processing**: Reads journal entries sequentially and forwards them one-by-one without buffering or using additional disk space.
- **Protocol Support**: Handles UDP, TCP, TLS (for encrypted transmission), and DTLS (Datagram Transport Layer Security, RFC 6012).
- **Flexible Formatting**: Supports RFC 5424 (default), RFC 5425 (with length prefix, ideal for TLS), and RFC 3339.
- **Security Options**: Certificate validation for TLS/DTLS, keepalive mechanisms, and exclusion filters for sensitive logs.
- **Namespace Awareness**: Can target specific journal namespaces or aggregate from multiple ones.
- **Runs as Dedicated User**: Operates under the `systemd-journal-netlog` system user for isolation.

systemd-netlogd is designed for minimal overhead, making it suitable for edge devices, servers, or cloud environments where centralized logging is needed without local storage impact.

## Installation

### Prerequisites
Ensure your system has the necessary build tools and dependencies. systemd-netlogd requires a recent systemd version (v255+ recommended for full feature support).

#### On Debian/Ubuntu
```bash
sudo apt update
sudo apt install build-essential gperf libcap-dev libsystemd-dev pkg-config meson python3-sphinx
```

#### On CentOS/RHEL/Fedora
```bash
sudo dnf group install 'Development Tools'
sudo dnf install gperf libcap-devel pkg-config systemd-devel meson python3-sphinx
```

### Building from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/systemd/systemd-netlogd.git
   cd systemd-netlogd
   ```

2. Build and install:
   ```bash
   meson setup build
   meson compile -C build
   sudo meson install -C build
   ```

   *Note*: If using traditional `make`, run `make` followed by `sudo make install`. Meson is preferred for modern builds.

3. Create the dedicated system user:
   - **Manual Creation**:
     ```bash
     sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog
     ```
   - **Via Sysusers** (recommended, if supported):
     Include the following in `/etc/sysusers.d/systemd-netlogd.conf` or use the provided file:
     ```
     #Type   Name                    ID                      GECOS   Home directory  Shell
     u       systemd-journal-netlog  -                        -       /               /bin/nologin
     ```
     Then run:
     ```bash
     sudo systemd-sysusers
     ```

### Package Managers
- **Ubuntu**: Available in the universe repository for supported releases (e.g., Plucky Puffin, Questing Quokka, Resolute Raccoon) with version 1.4.4-1. Install with `sudo apt update && sudo apt install systemd-netlogd`.
- **Fedora**: Available in COPR repositories (search for `systemd-netlogd`).
- **Arch Linux**: Build from AUR (`systemd-netlogd-git`).
- Check your distro's repositories for pre-built packages to simplify installation.

## Running the Service

After installation, enable and start the systemd service:

```bash
sudo systemctl daemon-reload  # Reload after installation
sudo systemctl enable --now systemd-netlogd.service
```

- **Service File Location**: `/lib/systemd/system/systemd-netlogd.service` (installed during build).
- **Logs**: Monitor with `journalctl -u systemd-netlogd.service`.
- **Manual Start**: `sudo systemd-netlogd` (for testing; use the service in production).

The daemon will bind to the configured address/port and begin forwarding journal entries immediately upon network availability.

## Configuration

systemd-netlogd uses drop-in configuration files:
- Main file: `/etc/systemd/netlogd.conf`
- Drop-ins: `/etc/systemd/netlogd.conf.d/*.conf` (INI format, processed in lexicographical order)

Configurations are parsed as INI files with a `[Network]` section. Reload changes with `sudo systemctl reload systemd-netlogd.service`.

### [Network] Section Options

| Option                  | Description | Default | Example |
|-------------------------|-------------|---------|---------|
| `Address=` | Destination for forwarding (unicast IP:port or multicast group:port, e.g., `192.168.1.100:514` or `239.0.0.1:6000`). Supports socket-unit-like syntax (see `systemd.socket(5)`). | None (required) | `Address=192.168.1.100:514` |
| `Protocol=` | Transport protocol: `udp` (default), `tcp`, `tls`, or `dtls`. | `udp` | `Protocol=tls` |
| `LogFormat=` | Output format: `rfc5424` (default), `rfc5425` (length-prefixed for TLS), or `rfc3339`. | `rfc5424` | `LogFormat=rfc5425` |
| `Directory=` | Custom journal directory path (overrides default runtime/system journals). | System default | `Directory=/var/log/journal-custom` |
| `Namespace=` | Journal namespace filter: string ID, `*` (all), or `+ID` (ID + default). | Default namespace | `Namespace=*` |
| `ConnectionRetrySec=` | Delay between retry attempts to the log server (time span, e.g., `1min`). Minimum 1s. | `30s` | `ConnectionRetrySec=1min` |
| `TLSCertificateAuthMode=` | TLS/DTLS cert validation: `no` (skip), `allow` (accept invalid), `deny` (reject invalid), `warn` (log but accept). | `deny` | `TLSCertificateAuthMode=warn` |
| `TLSServerCertificate=` | Path to PEM-formatted CA/server certificate for validation. | None | `TLSServerCertificate=/etc/ssl/ca-cert.pem` |
| `KeepAlive=` | Enable TCP keepalives (boolean). | `false` | `KeepAlive=true` |
| `KeepAliveTimeSec=` | Idle time before sending keepalive probes (seconds). | `7200` (2h) | `KeepAliveTimeSec=3600` |
| `KeepAliveIntervalSec=` | Interval between keepalive probes (seconds). | `75` | `KeepAliveIntervalSec=60` |
| `KeepAliveProbes=` | Number of unacknowledged probes before closing connection. | `9` | `KeepAliveProbes=5` |
| `SendBuffer=` | Socket send buffer size (e.g., `64K`, supports K/M/G suffixes). | System default | `SendBuffer=1M` |
| `NoDelay=` | Disable Nagle's algorithm for low-latency TCP (boolean). | `false` | `NoDelay=true` |
| `StructuredData=` | Custom syslog structured data ID (e.g., for cloud providers like Loggly). | None | `StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]` |
| `UseSysLogStructuredData=` | Extract and include `SYSLOG_STRUCTURED_DATA` from journal (boolean). | `false` | `UseSysLogStructuredData=yes` |
| `UseSysLogMsgId=` | Extract and include `SYSLOG_MSGID` from journal (boolean). | `false` | `UseSysLogMsgId=yes` |
| `ExcludeSyslogFacility=` | Comma-separated list of facilities to skip (e.g., `auth,authpriv`). See syslog facilities list below. | None | `ExcludeSyslogFacility=auth,daemon` |
| `ExcludeSyslogLevel=` | Comma-separated list of levels to skip (e.g., `debug`). See syslog levels list below. | None | `ExcludeSyslogLevel=debug,info` |

#### Syslog Facilities
Supported values: `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `ntp`, `security`, `console`, `solaris-cron`, `local0`–`local7`.

#### Syslog Levels
Supported values: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`.

### Configuration Examples

#### Example 1: UDP Multicast
For broadcasting to a multicast group:
```ini
[Network]
Address=239.0.0.1:6000
# Protocol=udp (default)
# LogFormat=rfc5424 (default)
```

#### Example 2: Unicast UDP with RFC 3339
```ini
[Network]
Address=192.168.8.101:514
# Protocol=udp (default)
LogFormat=rfc3339
```

#### Example 3: RFC 5424 with Custom Structured Data
Useful for cloud syslog services:
```ini
[Network]
Address=192.168.8.101:514
# Protocol=udp (default)
LogFormat=rfc5424
StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]
```

#### Example 4: Extracting Journal Metadata
Include structured data and message IDs from journal entries:
```ini
[Network]
Address=192.168.8.101:514
# Protocol=udp (default)
LogFormat=rfc5424
UseSysLogStructuredData=yes
UseSysLogMsgId=yes
```

#### Example 5: Filtering Sensitive Logs
Skip auth-related facilities and debug levels:
```ini
[Network]
Address=192.168.8.101:514
# Protocol=udp (default)
LogFormat=rfc3339
ExcludeSyslogFacility=auth,authpriv
ExcludeSyslogLevel=debug
```

#### Example 6: TLS with Relaxed Certificate Validation
For secure transmission with warning on invalid certs:
```ini
[Network]
Address=192.168.8.101:4433
Protocol=tls
# LogFormat=rfc5424 (default)
TLSCertificateAuthMode=warn
TLSServerCertificate=/etc/ssl/my-ca.pem
KeepAlive=true
```

#### Example 7: DTLS for UDP-Like Security
Datagram-based encryption:
```ini
[Network]
Address=192.168.8.101:4433
Protocol=dtls
# LogFormat=rfc5424 (default)
TLSCertificateAuthMode=allow
```

### Using Structured Data and Message IDs
To leverage `UseSysLogStructuredData` and `UseSysLogMsgId`, tag journal entries with metadata via `sd_journal_send()`:

```c
#include <systemd/sd-journal.h>

int main() {
    sd_journal_send(
        "MESSAGE=%s", "Message to process",
        "PRIORITY=%s", "4",  // warning level
        "SYSLOG_FACILITY=%s", "1",  // user facility
        "SYSLOG_MSGID=%s", "1011",
        "SYSLOG_STRUCTURED_DATA=%s", R"([exampleSDID@32473 iut="3" eventSource="Application"])",
        NULL
    );
    return 0;
}
```

Compile with: `gcc example.c -lsystemd`.

This embeds metadata that systemd-netlogd can extract and forward in syslog headers.

## Security Considerations
- **TLS/DTLS**: Always use certificate validation (`deny` mode) in production. Provide custom CAs via `TLSServerCertificate`.
- **Firewall**: Open only necessary ports (e.g., 514/UDP for syslog, 4433/TCP for TLS).
- **Exclusions**: Filter sensitive facilities (e.g., `authpriv`) to avoid leaking credentials.
- **Multicast**: Limit to trusted networks to prevent unauthorized log access.
- **User Isolation**: The `systemd-journal-netlog` user has minimal privileges; audit with `systemd-analyze security systemd-netlogd.service`.

## Troubleshooting
- **No Logs Forwarded**: Check `journalctl -u systemd-netlogd` for errors. Verify network connectivity and journal permissions.
- **Connection Failures**: Increase `ConnectionRetrySec` or inspect TLS certs with `openssl verify`.
- **High Latency**: Enable `NoDelay=true` for TCP; monitor buffer overflows with `SendBuffer`.
- **Testing**: Use `nc -u 192.168.8.101 514` to simulate a receiver and `logger -p user.info "Test message"` to generate journal entries.
- **Debug Mode**: Add `StandardOutput=journal+console` to the service override for verbose output.

## Contributing
Fork the repo, submit PRs for features/bugfixes. See `CONTRIBUTING.md` for guidelines.

## License
LGPL-2.1-or-later (same as systemd). See `LICENSE` file.

For questions, open an issue on GitHub.
