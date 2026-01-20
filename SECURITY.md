# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| 1.3.x   | :white_check_mark: |
| < 1.3   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in systemd-netlogd, please follow these steps:

### Where to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues to:
- Email: ssahani@gmail.com
- Subject line: "[SECURITY] systemd-netlogd: <brief description>"

### What to Include

Please provide as much information as possible:

1. **Description**: Clear description of the vulnerability
2. **Impact**: What could an attacker achieve?
3. **Reproduction**: Step-by-step instructions to reproduce the issue
4. **Affected Versions**: Which versions are affected?
5. **Proposed Fix**: If you have suggestions for a fix (optional)
6. **CVE**: If you've already obtained a CVE identifier (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days with assessment and planned fix timeline
- **Fix Release**: Depends on severity:
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Next regular release

### Disclosure Policy

We follow responsible disclosure:

1. You report the issue privately
2. We confirm receipt and assess severity
3. We develop and test a fix
4. We release the fix in a security update
5. We publicly disclose the issue after users have had time to update (typically 7-14 days)

We will credit security researchers in our release notes unless they prefer to remain anonymous.

## Security Considerations

### TLS/DTLS Configuration

When using TLS or DTLS for log transmission:

- **Always use certificate verification** in production (`CertificateAuthentication=deny`)
- Use `CertificateAuthentication=warn` only for testing
- Never use `CertificateAuthentication=allow` in production
- Keep OpenSSL libraries up to date
- Use certificates from trusted CAs

### Network Security

- systemd-netlogd runs with limited capabilities (`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_BROADCAST`)
- Drops privileges to the `systemd-journal-netlog` user after initialization
- Consider using firewall rules to restrict outbound connections to trusted log servers

### Journal Access

- The daemon only reads from the systemd journal (no write access)
- Journal filtering (facilities, levels) happens before network transmission
- Ensure journal permissions are properly configured

### State File Security

- State file (cursor position) is stored in `/var/lib/systemd/journal-netlogd/state`
- Permissions are automatically set to `0644`
- Contains only cursor information, no sensitive data

## Known Security Considerations

### Log Injection

Applications can write arbitrary content to the journal, which is then forwarded. Receiving syslog servers should:
- Properly validate and sanitize incoming log messages
- Implement rate limiting
- Use structured data parsing with care

### Network Attacks

- **Man-in-the-Middle**: Use TLS/DTLS with certificate verification
- **Denial of Service**: systemd-netlogd includes rate limiting, but ensure your syslog server also has DoS protection
- **Replay Attacks**: TLS/DTLS provide replay protection

### Information Disclosure

- Logs may contain sensitive information
- Use TLS/DTLS encryption for log transmission
- Ensure syslog server security and access controls
- Consider log retention and disposal policies

## Security Updates

Security updates are announced via:
- GitHub Security Advisories
- Git commit messages tagged with `[SECURITY]`
- CHANGELOG.md entries under "Security" section

Subscribe to repository notifications to stay informed.

## Security Best Practices

1. **Keep Updated**: Always run the latest supported version
2. **Use Encryption**: Enable TLS/DTLS for remote log transmission
3. **Verify Certificates**: Use strict certificate authentication
4. **Filter Logs**: Only forward necessary log levels and facilities
5. **Monitor**: Track systemd-netlogd status and errors
6. **Network Segmentation**: Isolate log infrastructure on dedicated networks
7. **Regular Audits**: Periodically review configuration and security settings

## Contact

For security-related questions or concerns:
- Email: ssahani@gmail.com
- PGP Key: (if available, include fingerprint or link)
