# Configuration Examples

This directory contains example configurations for common use cases.

## Using These Examples

1. Copy the example to `/etc/systemd/netlogd.conf.d/`:
   ```bash
   sudo cp example-name.conf /etc/systemd/netlogd.conf.d/
   ```

2. Edit as needed for your environment

3. Reload configuration:
   ```bash
   sudo systemctl reload systemd-netlogd
   ```

## Available Examples

| File | Description |
|------|-------------|
| `basic-udp.conf` | Simple UDP multicast setup |
| `basic-tcp.conf` | Reliable TCP forwarding |
| `tls-secure.conf` | Encrypted TLS with certificate validation |
| `dtls-encrypted.conf` | DTLS encrypted datagrams |
| `cloud-papertrail.conf` | Configuration for Papertrail cloud service |
| `cloud-loggly.conf` | Configuration for Loggly cloud service |
| `filtering.conf` | Filter sensitive logs |
| `structured-data.conf` | Use structured data fields |
| `high-performance.conf` | Optimized for high-volume logging |
| `development.conf` | Development/testing setup |

## Testing Examples

Start a simple receiver to test:

```bash
# UDP receiver
nc -ul 514

# TCP receiver
nc -l 514
```

Then generate test logs:

```bash
logger -p user.info "Test message"
```

## Security Note

Never use UDP or TCP without encryption over untrusted networks. Always use TLS or DTLS when sending logs over the internet.
