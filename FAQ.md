# Frequently Asked Questions (FAQ)

## General Questions

### What is systemd-netlogd?

systemd-netlogd is a lightweight daemon that forwards systemd journal logs to remote syslog servers over the network. It's designed for centralized logging without local storage impact.

### How is it different from systemd-journal-remote?

| Feature | systemd-netlogd | systemd-journal-remote |
|---------|-----------------|------------------------|
| Direction | Local → Remote (push) | Remote → Local (pull) |
| Protocol | Syslog (RFC 5424/3339) | systemd Journal Export |
| Use Case | Send logs to syslog servers | Receive logs from remote systemd hosts |
| Storage | Zero buffering | Stores in local journal |

### Why not use rsyslog or syslog-ng?

You can! systemd-netlogd is complementary:
- **Simpler**: Fewer configuration options, easier to deploy
- **Lighter**: Minimal resource footprint
- **Native**: Reads directly from systemd journal (no imjournal module needed)
- **Focused**: One job - forward journal to network

Use rsyslog/syslog-ng if you need:
- Complex routing rules
- Local log processing
- Non-journal sources

## Installation and Setup

### Do I need root privileges to run systemd-netlogd?

No. It runs as the unprivileged `systemd-journal-netlog` user. Root is only needed for:
- Installation
- Creating the system user
- Managing the systemd service

### What systemd version is required?

**Minimum**: systemd v230 (released 2016)
**Recommended**: systemd v255+ for full features

Check your version:
```bash
systemctl --version
```

### Can I install it without building from source?

Yes, packages are available for some distributions:
- **Ubuntu**: Plucky, Quokka, Raccoon and later: `sudo apt install systemd-netlogd`
- **Fedora**: Search COPR repositories
- **Arch Linux**: AUR package `systemd-netlogd-git`

## Configuration

### Where is the configuration file?

Main config: `/etc/systemd/netlogd.conf`

Drop-in configs: `/etc/systemd/netlogd.conf.d/*.conf`

Use drop-ins for environment-specific overrides:
```bash
sudo mkdir -p /etc/systemd/netlogd.conf.d
sudo tee /etc/systemd/netlogd.conf.d/production.conf <<EOF
[Network]
Address=logs.production.example.com:514
Protocol=tls
EOF
```

### How do I reload configuration without restarting?

```bash
sudo systemctl reload systemd-netlogd
```

This reloads the config without losing the journal cursor position.

### Can I forward logs to multiple destinations?

Not currently. systemd-netlogd supports a single destination.

**Workarounds:**
1. Run multiple instances with different config files (advanced)
2. Use a syslog server as intermediary to fan out to multiple destinations
3. Use rsyslog or syslog-ng for multi-destination forwarding

### How do I prevent sensitive logs from being forwarded?

Use facility or level filtering:

```ini
[Network]
Address=192.168.1.100:514
# Don't forward authentication logs
ExcludeSyslogFacility=auth authpriv
# Don't forward debug messages
ExcludeSyslogLevel=debug
```

## Network and Protocols

### Which protocol should I use: UDP, TCP, TLS, or DTLS?

**UDP**:
- ✓ Lowest overhead
- ✓ Fire-and-forget
- ✗ No delivery guarantee
- ✗ Unencrypted
- **Use for**: High-volume, local networks

**TCP**:
- ✓ Reliable delivery
- ✓ Connection-oriented
- ✗ Unencrypted
- ✗ Higher overhead
- **Use for**: Reliable delivery over trusted networks

**TLS**:
- ✓ Encrypted
- ✓ Reliable delivery
- ✓ Best for internet
- ✗ Highest overhead
- **Use for**: Sending logs over untrusted networks

**DTLS**:
- ✓ Encrypted
- ✓ Lower latency than TLS
- ✗ Less common support
- **Use for**: Low-latency encrypted datagrams

### Can I use multicast?

Yes, with UDP:

```ini
[Network]
Address=239.0.0.1:6000
Protocol=udp
```

Ensure your network supports multicast and receivers join the group.

### What happens if the remote server is down?

1. Connection fails
2. systemd-netlogd schedules reconnect after `ConnectionRetrySec` (default 30s)
3. Journal cursor is NOT advanced (messages will be replayed)
4. Automatic reconnection when network comes back

To check retry interval:
```bash
grep ConnectionRetrySec /etc/systemd/netlogd.conf
```

### How do I test TLS connectivity?

Use OpenSSL s_client:

```bash
openssl s_client -connect your-server:6514 -CAfile /path/to/ca.pem
```

If successful, you'll see certificate details and "Verify return code: 0 (ok)".

### Can I use a self-signed certificate?

Yes, with proper configuration:

**Option 1**: Use `allow` mode (accepts all certs)
```ini
TLSCertificateAuthMode=allow
```

**Option 2**: Provide the self-signed cert as CA
```ini
TLSCertificateAuthMode=deny
TLSServerCertificate=/path/to/self-signed-cert.pem
```

## Log Formats

### What's the difference between RFC 5424 and RFC 3339?

**RFC 5424** (recommended):
```
<34>1 2024-01-20T10:30:15.123456+00:00 hostname myapp 1234 - - User logged in
```
- Version field (1)
- Structured data support
- Modern syslog standard

**RFC 3339** (legacy):
```
<34>2024-01-20T10:30:15.123456+00:00 hostname myapp[1234]: User logged in
```
- BSD syslog format
- No structured data
- Compatible with older servers

**Use RFC 5424** unless your server doesn't support it.

### What is RFC 5425?

RFC 5425 is the TLS transport mapping for syslog. It uses length-prefixed framing:

```
123 <34>1 2024-01-20T10:30:15...
```

systemd-netlogd automatically uses RFC 5425 framing when:
```ini
Protocol=tls
LogFormat=rfc5425
```

### Can I add custom fields to log messages?

Yes, using structured data:

```ini
[Network]
LogFormat=rfc5424
StructuredData=[app@12345 env="production" region="us-east"]
```

Or extract from journal:
```ini
UseSysLogStructuredData=yes
UseSysLogMsgId=yes
```

Then tag journal entries:
```c
sd_journal_send(
    "MESSAGE=Event occurred",
    "SYSLOG_STRUCTURED_DATA=[app@12345 user=\"alice\"]",
    "SYSLOG_MSGID=EVENT001",
    NULL
);
```

## Journal and Storage

### Does systemd-netlogd buffer messages to disk?

No. It reads the journal sequentially and forwards immediately. This is intentional for:
- Minimal storage impact
- Real-time forwarding
- Simplicity

### What happens if I send more logs than the network can handle?

1. **Rate limiting**: Default 10 messages per 10 seconds prevents flooding
2. **Backpressure**: If network is slow, journal reading pauses
3. **No message loss**: Cursor tracks position, messages replayed on reconnect

### Can I forward logs from a specific namespace?

Yes:

```ini
[Network]
# Forward only from namespace "app"
Namespace=app

# Forward from all namespaces
Namespace=*

# Forward from default + namespace "app"
Namespace=+app
```

### How do I monitor the journal cursor position?

Check the state file:

```bash
sudo cat /var/lib/systemd-netlogd/state
```

Shows:
```
LAST_CURSOR=s=abc123def456...
```

This cursor tracks the last successfully forwarded entry.

### Can I start forwarding from a specific point in time?

Yes, use the cursor option:

1. Get cursor for a timestamp:
```bash
journalctl --since="2024-01-20 10:00:00" --show-cursor
```

2. Edit state file:
```bash
sudo tee /var/lib/systemd-netlogd/state <<EOF
LAST_CURSOR=s=your-cursor-here
EOF
```

3. Restart:
```bash
sudo systemctl restart systemd-netlogd
```

## Performance

### How much CPU and memory does it use?

Very minimal:
- **Memory**: ~2-5 MB RSS
- **CPU**: <1% on typical workloads

Optimized for efficiency:
- Event-driven (no polling)
- Zero buffering
- Single-threaded

### Can it handle high-volume logging?

Yes, with caveats:
- **Tested**: Up to ~10,000 messages/second (with rate limiting disabled)
- **Network-bound**: Limited by network bandwidth, not CPU
- **No queuing**: If network is slower than log generation, backpressure occurs

For extreme volumes:
1. Disable rate limiting
2. Use UDP for lowest overhead
3. Consider local aggregation with rsyslog first

### Does it impact journal performance?

No. It reads the journal like any other reader (journalctl, etc.). The journal is designed for concurrent access.

## Troubleshooting

### No logs are being forwarded. How do I debug?

1. **Check service status**:
   ```bash
   sudo systemctl status systemd-netlogd
   ```

2. **View logs**:
   ```bash
   journalctl -u systemd-netlogd -f
   ```

3. **Enable debug logging**:
   ```bash
   sudo systemctl edit systemd-netlogd
   ```
   Add:
   ```ini
   [Service]
   Environment=SYSTEMD_LOG_LEVEL=debug
   ```

4. **Test connectivity**:
   ```bash
   nc -vz your-server 514  # UDP
   nc -vz your-server 514  # TCP
   ```

5. **Verify config**:
   ```bash
   cat /etc/systemd/netlogd.conf
   ```

6. **Test receiver**:
   ```bash
   nc -ul 514  # Listen UDP
   ```

### I see "Connection refused" errors

Possible causes:
1. **Firewall blocking**: Check firewall rules
2. **Server not running**: Start syslog server on remote
3. **Wrong port**: Verify port number (514 for syslog, 6514 for TLS)
4. **Wrong protocol**: Ensure server supports your protocol (TCP/UDP/TLS)

Test:
```bash
# Test UDP
echo "test" | nc -u your-server 514

# Test TCP
echo "test" | nc your-server 514
```

### TLS handshake fails

Common issues:

1. **Wrong CA certificate**:
   ```bash
   # Test manually
   openssl s_client -connect server:6514 -CAfile /path/to/ca.pem
   ```

2. **Certificate verification mode too strict**:
   ```ini
   # Try warn mode for debugging
   TLSCertificateAuthMode=warn
   ```

3. **Server requires client cert**:
   systemd-netlogd currently doesn't support client certificates

4. **Certificate expired**:
   ```bash
   # Check expiration
   openssl x509 -in /path/to/ca.pem -noout -dates
   ```

### Logs are delayed or batched

This is normal behavior for journal reading. To reduce latency:

1. **Use TCP_NODELAY** (disables Nagle algorithm):
   ```ini
   NoDelay=yes
   ```

2. **Reduce retry interval**:
   ```ini
   ConnectionRetrySec=5
   ```

3. **Check network latency**:
   ```bash
   ping your-server
   ```

### How do I completely reset the state?

To start from scratch:

```bash
# Stop service
sudo systemctl stop systemd-netlogd

# Remove state file
sudo rm /var/lib/systemd-netlogd/state

# Start service (will start from current journal position)
sudo systemctl start systemd-netlogd
```

## Security

### Is it safe to send logs over the internet?

**Only with TLS**:

```ini
[Network]
Address=logs.example.com:6514
Protocol=tls
TLSCertificateAuthMode=deny
TLSServerCertificate=/etc/ssl/certs/ca-bundle.pem
```

Never use UDP or TCP over untrusted networks - logs are sent in plaintext.

### Can logs contain sensitive information?

Yes. Best practices:

1. **Filter sensitive facilities**:
   ```ini
   ExcludeSyslogFacility=auth authpriv
   ```

2. **Review what's logged**: Audit applications to avoid logging credentials

3. **Use TLS**: Encrypt in transit

4. **Secure remote server**: Protect the destination server

### How do I verify certificate validation is working?

1. **Check logs** for validation messages:
   ```bash
   journalctl -u systemd-netlogd | grep -i certificate
   ```

2. **Test with invalid cert**:
   ```ini
   TLSCertificateAuthMode=deny
   TLSServerCertificate=/path/to/wrong-ca.pem
   ```
   Should fail to connect.

3. **Test with valid cert**: Should connect successfully

## Advanced Usage

### Can I run multiple instances?

Yes, with systemd templates (advanced):

1. Create template: `/etc/systemd/system/systemd-netlogd@.service`
2. Create configs: `/etc/systemd/netlogd-prod.conf`, `/etc/systemd/netlogd-dev.conf`
3. Start instances: `systemctl start systemd-netlogd@prod systemd-netlogd@dev`

This is not officially supported but technically possible.

### Can I filter logs by content (regex)?

Not currently. systemd-netlogd only supports facility and level filtering.

For content-based filtering, use:
- rsyslog with imjournal + filters
- syslog-ng with journal source + filters

### How do I send logs to cloud services (Papertrail, Loggly, etc.)?

These services typically provide a syslog endpoint:

**Papertrail**:
```ini
[Network]
Address=logs7.papertrailapp.com:12345
Protocol=tls
LogFormat=rfc5424
```

**Loggly**:
```ini
[Network]
Address=logs-01.loggly.com:6514
Protocol=tls
LogFormat=rfc5424
StructuredData=[YOUR-LOGGLY-TOKEN@41058]
```

Check your service's documentation for exact settings.

### Can I compress logs?

Not currently. This is a planned future enhancement.

Workaround: Use a local syslog server (rsyslog/syslog-ng) as intermediary with compression support.

## Contributing

### How can I contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Quick start:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Where do I report bugs?

Create an issue on GitHub:
https://github.com/systemd/systemd-netlogd/issues

Include:
- systemd-netlogd version
- Operating system and version
- Configuration file
- Relevant logs
- Steps to reproduce

### How do I request a feature?

Create a feature request issue with:
- Use case description
- Proposed solution
- Why it can't be achieved with current features

## Getting Help

### Where can I get support?

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **IRC**: #systemd on irc.libera.chat (for systemd-related questions)

### Is commercial support available?

systemd-netlogd is a community project. For enterprise support, contact your Linux distribution vendor or consider rsyslog/syslog-ng commercial offerings.

## Additional Resources

- [README.md](README.md) - Getting started guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal architecture
- [TESTING.md](TESTING.md) - Testing guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [RFC 5424](https://tools.ietf.org/html/rfc5424) - Syslog protocol specification
- [systemd Journal](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)
