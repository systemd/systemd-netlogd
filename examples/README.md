# Configuration Examples

This directory contains example configurations for common use cases.

## Quick Start

### 1. Choose Your Example

Pick an example that matches your use case:

- **Testing locally?** → `basic-udp.conf` or `development.conf`
- **Internal network?** → `basic-tcp.conf` with optional `filtering.conf`
- **Production remote?** → `tls-secure.conf` or `tls-production.conf`
- **Cloud service?** → `cloud-papertrail.conf`, `cloud-loggly.conf`, or `cloud-splunk.conf`
- **High volume?** → `high-performance.conf`

### 2. Install Configuration

```bash
# Create config directory if it doesn't exist
sudo mkdir -p /etc/systemd/netlogd.conf.d/

# Copy and customize your chosen example
sudo cp examples/your-choice.conf /etc/systemd/netlogd.conf.d/10-myconfig.conf
sudo ${EDITOR:-vi} /etc/systemd/netlogd.conf.d/10-myconfig.conf
```

### 3. Enable and Start

```bash
# Enable the service to start on boot
sudo systemctl enable systemd-netlogd

# Start the service
sudo systemctl start systemd-netlogd

# Check status
sudo systemctl status systemd-netlogd

# View logs
sudo journalctl -u systemd-netlogd -f
```

### 4. Verify It Works

```bash
# Generate a test log message
logger -p user.info "Test message from systemd-netlogd"

# Check if systemd-netlogd is forwarding
sudo journalctl -u systemd-netlogd -n 20
```

## Available Examples

### Basic Configurations

| File | Use Case | Transport | Security |
|------|----------|-----------|----------|
| `basic-udp.conf` | Local testing, low-latency | UDP | None |
| `basic-tcp.conf` | Reliable local forwarding | TCP | None |
| `multicast.conf` | Multiple receivers on LAN | UDP Multicast | None |

### Secure Configurations

| File | Use Case | Transport | Security |
|------|----------|-----------|----------|
| `tls-secure.conf` | Basic TLS setup | TLS | Certificate validation |
| `tls-production.conf` | Production-ready TLS | TLS | Full validation + extras |
| `dtls-encrypted.conf` | Low-latency encrypted | DTLS | Certificate validation |
| `tls-mutual.conf` | Mutual TLS authentication | TLS | Client + Server certs |

### Cloud Service Configurations

| File | Service | Documentation |
|------|---------|---------------|
| `cloud-papertrail.conf` | Papertrail | https://papertrailapp.com |
| `cloud-loggly.conf` | Loggly | https://loggly.com |
| `cloud-splunk.conf` | Splunk Cloud | https://splunk.com |
| `cloud-datadog.conf` | Datadog | https://datadoghq.com |

### Advanced Configurations

| File | Purpose |
|------|---------|
| `filtering.conf` | Filter by facility and severity |
| `structured-data.conf` | Add custom structured data fields |
| `high-performance.conf` | Optimize for high-volume logging |
| `namespace.conf` | Forward specific journal namespace |
| `development.conf` | Development and testing setup |
| `monitoring.conf` | Integration with monitoring systems |

## Testing Your Configuration

### Local Testing with Netcat

```bash
# Terminal 1: Start a receiver
nc -ul 6000  # For UDP
# or
nc -l 6000   # For TCP

# Terminal 2: Configure systemd-netlogd to use localhost:6000
sudo systemctl restart systemd-netlogd

# Terminal 3: Send test logs
logger -p user.notice "Test notice message"
logger -p user.warning "Test warning message"
logger -p user.err "Test error message"

# You should see RFC 5424 formatted messages in Terminal 1
```

### Testing with Docker

See `docker-compose.yml` for a complete testing environment with rsyslog receiver.

```bash
# Start rsyslog receiver
docker-compose up -d

# Configure systemd-netlogd to use localhost:10514
# ... configure and restart service ...

# Send test messages
logger -t myapp "Docker test message"

# View received logs
docker-compose logs syslog-receiver
```

### Testing TLS Configuration

```bash
# Verify TLS connection
openssl s_client -connect logs.example.com:6514 -showcerts

# Test certificate validation
sudo systemd-netlogd --test /etc/systemd/netlogd.conf

# Monitor connection status
sudo journalctl -u systemd-netlogd -f | grep -i "tls\|ssl\|cert"
```

## Troubleshooting

### Service Won't Start

```bash
# Check configuration syntax
sudo systemd-analyze verify systemd-netlogd.service

# Check for configuration errors
sudo systemd-netlogd --test

# View detailed errors
sudo journalctl -u systemd-netlogd -xe
```

### No Logs Being Forwarded

```bash
# Verify network connectivity
ping logs.example.com
telnet logs.example.com 6514

# Check firewall rules
sudo iptables -L -n | grep 6514
sudo firewall-cmd --list-all

# Verify journal is producing logs
journalctl -f

# Check systemd-netlogd status
sudo systemctl status systemd-netlogd -l
```

### TLS Certificate Issues

```bash
# Verify certificate file exists and is readable
ls -l /etc/pki/tls/certs/ca-bundle.crt
sudo cat /etc/pki/tls/certs/ca-bundle.crt | head

# Test with relaxed validation (temporary, for debugging only)
# Set TLSCertificateAuthMode=warn in config

# Check OpenSSL version
openssl version

# Verify server certificate
echo | openssl s_client -connect logs.example.com:6514 2>/dev/null | openssl x509 -noout -text
```

### High CPU or Memory Usage

```bash
# Check journal message rate
journalctl --since "1 hour ago" | wc -l

# Use filtering to reduce volume
# Add ExcludeSyslogLevel=debug info to config

# Monitor resource usage
top -p $(pgrep systemd-netlogd)
systemd-cgtop
```

## Configuration Tips

### 1. Use Filtering to Reduce Noise

```ini
[Network]
# Don't forward debug and info messages
ExcludeSyslogLevel=debug info

# Don't forward authentication logs (may contain sensitive data)
ExcludeSyslogFacility=auth authpriv
```

### 2. Enable Connection Persistence for TCP/TLS

```ini
[Network]
KeepAlive=yes          # Keep connections alive
NoDelay=yes            # Disable Nagle's algorithm for lower latency
ConnectionRetrySec=30  # Retry every 30 seconds if connection fails
```

### 3. Add Context with Structured Data

```ini
[Network]
StructuredData=[meta@32473 environment="production" datacenter="us-east-1" hostname="web-server-01"]
```

### 4. Test Changes Safely

```bash
# Validate configuration before applying
sudo systemd-netlogd --test /etc/systemd/netlogd.conf.d/10-myconfig.conf

# Reload without interruption
sudo systemctl reload systemd-netlogd

# If something breaks, revert
sudo mv /etc/systemd/netlogd.conf.d/10-myconfig.conf{,.bak}
sudo systemctl restart systemd-netlogd
```

## Security Best Practices

⚠️ **IMPORTANT**: Follow these security guidelines:

1. **Use Encryption**: Always use TLS or DTLS for logs sent over the internet
2. **Validate Certificates**: Set `TLSCertificateAuthMode=deny` in production
3. **Filter Sensitive Data**: Exclude auth logs that may contain passwords
4. **Restrict Network Access**: Use firewall rules to limit outbound connections
5. **Keep Software Updated**: Regularly update systemd-netlogd and OpenSSL
6. **Monitor for Errors**: Set up alerts for certificate expiration and connection failures

## Performance Tuning

For high-volume logging (>10,000 messages/sec):

1. Use `high-performance.conf` as a starting point
2. Consider UDP or DTLS instead of TCP/TLS for lower latency
3. Use filtering to reduce volume
4. Monitor systemd-netlogd resource usage
5. Tune journal settings (`/etc/systemd/journald.conf`)

## Getting Help

- Read the manual: `man systemd-netlogd.conf`
- Check the FAQ: `FAQ.md`
- Report issues: https://github.com/systemd/systemd-netlogd/issues
- View architecture: `ARCHITECTURE.md`

## Contributing Examples

Have a useful configuration? Please contribute!

1. Create a new example file with detailed comments
2. Add it to this README
3. Test it thoroughly
4. Submit a pull request

See `CONTRIBUTING.md` for details.
