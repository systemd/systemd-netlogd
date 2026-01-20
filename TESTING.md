# Testing Guide for systemd-netlogd

This document provides comprehensive testing instructions for systemd-netlogd.

## Table of Contents

- [Unit Tests](#unit-tests)
- [Integration Tests](#integration-tests)
- [Manual Testing](#manual-testing)
- [Protocol Compliance Testing](#protocol-compliance-testing)
- [Security Testing](#security-testing)
- [Performance Testing](#performance-testing)
- [Continuous Integration](#continuous-integration)

## Unit Tests

### Running Unit Tests

```bash
# Build with tests
meson setup build
meson compile -C build

# Run all tests
meson test -C build

# Run with verbose output
meson test -C build -v

# Run specific test
meson test -C build test-protocol -v
meson test -C build test-string-tables -v
```

### Test Suite Overview

#### test-protocol
Tests RFC 3339 timestamp formatting:
- Specific timestamp formatting
- NULL timestamp (current time)
- Structure validation (T separator, timezone format)

#### test-string-tables
Tests string table conversions:
- Protocol names (udp, tcp, tls, dtls)
- Log formats (rfc5424, rfc3339, rfc5425)
- Syslog facilities (kern, user, mail, etc.)
- Syslog levels (emerg, alert, crit, etc.)

### Writing New Tests

Create a new test file in `tests/`:

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "your-module.h"

static void test_your_feature(void **state) {
        int result = your_function();
        assert_int_equal(result, EXPECTED_VALUE);
}

int main(void) {
        const struct CMUnitTest tests[] = {
                cmocka_unit_test(test_your_feature),
        };
        return cmocka_run_group_tests(tests, NULL, NULL);
}
```

Add to `tests/meson.build`:

```meson
test_your_module = executable(
        'test-your-module',
        'test-your-module.c',
        '../src/netlog/your-module.c',
        include_directories : includes,
        link_with : libshared,
        dependencies : [cmocka, test_libsystemd],
)

test('your-module', test_your_module)
```

## Integration Tests

### Test With Local Syslog Server

#### Option 1: Using netcat

Start a simple UDP receiver:
```bash
# Terminal 1: Start receiver
nc -ul 514

# Or for TCP
nc -l 514
```

Configure systemd-netlogd:
```ini
# /etc/systemd/netlogd.conf
[Network]
Address=127.0.0.1:514
Protocol=udp
```

Generate test logs:
```bash
logger -p user.info "Test message from systemd-netlogd"
logger -p user.warning "Another test message"
```

#### Option 2: Using rsyslog

Install and configure rsyslog:
```bash
sudo dnf install rsyslog
```

Configure `/etc/rsyslog.conf`:
```
# UDP listener
module(load="imudp")
input(type="imudp" port="514")

# TCP listener
module(load="imtcp")
input(type="imtcp" port="514")

# Log to file
*.* /var/log/netlogd-test.log
```

Restart rsyslog:
```bash
sudo systemctl restart rsyslog
```

Monitor logs:
```bash
tail -f /var/log/netlogd-test.log
```

#### Option 3: Using syslog-ng

```bash
sudo dnf install syslog-ng
```

Configure `/etc/syslog-ng/syslog-ng.conf`:
```
source s_network {
    udp(port(514));
    tcp(port(514));
};

destination d_netlogd_test {
    file("/var/log/netlogd-test.log");
};

log {
    source(s_network);
    destination(d_netlogd_test);
};
```

### TLS Testing

#### Generate Test Certificates

Create CA and server certificates:

```bash
#!/bin/bash
# generate-certs.sh

# Create CA
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=State/L=City/O=Test/CN=Test CA"

# Create server certificate
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server-req.pem \
    -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
openssl x509 -req -days 365 -in server-req.pem -CA ca-cert.pem \
    -CAkey ca-key.pem -CAcreateserial -out server-cert.pem

# Cleanup
rm server-req.pem
```

#### Start TLS Syslog Receiver

Using stunnel:
```bash
sudo dnf install stunnel

# Create stunnel config
cat > /etc/stunnel/syslog-tls.conf <<EOF
[syslog-tls]
accept = 6514
connect = 127.0.0.1:514
cert = /path/to/server-cert.pem
key = /path/to/server-key.pem
EOF

sudo systemctl start stunnel@syslog-tls
```

Configure systemd-netlogd:
```ini
[Network]
Address=localhost:6514
Protocol=tls
TLSCertificateAuthMode=allow
TLSServerCertificate=/path/to/ca-cert.pem
```

#### Test TLS Connection

Verify TLS handshake:
```bash
openssl s_client -connect localhost:6514 -CAfile ca-cert.pem
```

### DTLS Testing

DTLS requires specialized tools. Use OpenSSL s_server:

```bash
# Start DTLS server
openssl s_server -dtls -accept 4433 \
    -cert server-cert.pem -key server-key.pem \
    -CAfile ca-cert.pem
```

Configure systemd-netlogd:
```ini
[Network]
Address=localhost:4433
Protocol=dtls
TLSCertificateAuthMode=allow
TLSServerCertificate=/path/to/ca-cert.pem
```

## Manual Testing

### Test Scenarios

#### 1. Basic UDP Multicast

```bash
# Start receiver on multicast address
socat UDP4-RECVFROM:6000,ip-add-membership=239.0.0.1:0.0.0.0,fork -

# Configure systemd-netlogd (default config)
# Generate test log
logger "Test UDP multicast"
```

#### 2. TCP Reliable Delivery

```bash
# Configure for TCP
cat > /etc/systemd/netlogd.conf <<EOF
[Network]
Address=192.168.1.100:514
Protocol=tcp
KeepAlive=yes
NoDelay=yes
EOF

sudo systemctl reload systemd-netlogd

# Generate burst of messages
for i in {1..100}; do
    logger "Test message $i"
done
```

#### 3. Message Filtering

```bash
# Configure with filters
cat > /etc/systemd/netlogd.conf <<EOF
[Network]
Address=192.168.1.100:514
ExcludeSyslogFacility=auth authpriv
ExcludeSyslogLevel=debug info
EOF

sudo systemctl reload systemd-netlogd

# These should NOT be forwarded
logger -p auth.info "Auth message - filtered"
logger -p user.debug "Debug message - filtered"

# This SHOULD be forwarded
logger -p user.warning "Warning message - forwarded"
```

#### 4. Structured Data

```bash
# Configure for structured data
cat > /etc/systemd/netlogd.conf <<EOF
[Network]
Address=192.168.1.100:514
LogFormat=rfc5424
UseSysLogStructuredData=yes
UseSysLogMsgId=yes
EOF

# Send structured log (requires custom program)
systemd-cat -t myapp -p info <<EOF
SYSLOG_MSGID=LOGIN001
SYSLOG_STRUCTURED_DATA=[auth@12345 user="alice" ip="1.2.3.4"]
MESSAGE=User logged in successfully
EOF
```

#### 5. Connection Retry

```bash
# Configure short retry interval
cat > /etc/systemd/netlogd.conf <<EOF
[Network]
Address=192.168.1.100:514
Protocol=tcp
ConnectionRetrySec=5
EOF

sudo systemctl restart systemd-netlogd

# Start without server running
# Watch logs for retry attempts
journalctl -u systemd-netlogd -f

# Start server after a few retries
nc -l 514
```

### Debugging

#### Enable Debug Logging

Temporary (until restart):
```bash
sudo systemctl kill -s SIGUSR1 systemd-netlogd
```

Permanent:
```bash
sudo systemctl edit systemd-netlogd

# Add:
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
StandardOutput=journal+console
```

#### Trace System Calls

```bash
sudo strace -p $(pidof systemd-netlogd) -f -e trace=network
```

#### Monitor Network Traffic

```bash
# UDP
sudo tcpdump -i any -n udp port 514 -A

# TCP
sudo tcpdump -i any -n tcp port 514 -A

# TLS (encrypted)
sudo tcpdump -i any -n tcp port 6514 -X
```

#### Check Journal Cursor

```bash
sudo cat /var/lib/systemd-netlogd/state
```

## Protocol Compliance Testing

### RFC 5424 Compliance

Validate message format:

```python
#!/usr/bin/env python3
import re
import socket

# RFC 5424 pattern
RFC5424_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>(?P<ver>\d+) '
    r'(?P<ts>\S+) '
    r'(?P<host>\S+) '
    r'(?P<app>\S+) '
    r'(?P<proc>\S+) '
    r'(?P<msgid>\S+) '
    r'(?P<sd>\S+|\[.*?\]) '
    r'(?P<msg>.*)$'
)

# Start UDP listener
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 514))

print("Listening for syslog messages on UDP 514...")
while True:
    data, addr = sock.recvfrom(4096)
    msg = data.decode('utf-8', errors='replace')
    print(f"\nReceived from {addr}:")
    print(f"  Raw: {repr(msg)}")

    match = RFC5424_PATTERN.match(msg)
    if match:
        print("  ✓ RFC 5424 compliant")
        print(f"    Priority: {match.group('pri')}")
        print(f"    Version: {match.group('ver')}")
        print(f"    Timestamp: {match.group('ts')}")
        print(f"    Hostname: {match.group('host')}")
    else:
        print("  ✗ NOT RFC 5424 compliant")
```

### RFC 3339 Timestamp Validation

```python
from datetime import datetime

def validate_rfc3339(timestamp):
    """Validate RFC 3339 timestamp format"""
    try:
        # Format: YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM
        datetime.fromisoformat(timestamp.replace(':', '', 2).replace(':', '', 1))
        return True
    except ValueError:
        return False

# Test
ts = "2024-01-20T10:30:15.123456+05:30"
print(f"{ts}: {validate_rfc3339(ts)}")
```

## Security Testing

### Certificate Validation Testing

Test different validation modes:

```bash
# Test 1: Valid certificate (should succeed)
cat > /etc/systemd/netlogd.conf <<EOF
[Network]
Address=localhost:6514
Protocol=tls
TLSCertificateAuthMode=deny
TLSServerCertificate=/path/to/valid-ca.pem
EOF

# Test 2: Invalid certificate (should fail with deny)
TLSCertificateAuthMode=deny
TLSServerCertificate=/path/to/wrong-ca.pem

# Test 3: Expired certificate (should warn)
TLSCertificateAuthMode=warn

# Test 4: Self-signed (should work with allow)
TLSCertificateAuthMode=allow
```

### Privilege Testing

Verify it runs without elevated privileges:

```bash
# Check effective user
sudo systemctl show systemd-netlogd -p User

# Should be: User=systemd-journal-netlog

# Check capabilities
sudo systemd-analyze security systemd-netlogd

# Expected: ✓ Restrictive capabilities
```

## Performance Testing

### Message Throughput

Generate high-volume logs:

```bash
#!/bin/bash
# throughput-test.sh

echo "Starting throughput test..."
start=$(date +%s)
count=10000

for i in $(seq 1 $count); do
    logger -p user.info "Throughput test message $i"
done

end=$(date +%s)
duration=$((end - start))
rate=$((count / duration))

echo "Sent $count messages in $duration seconds"
echo "Rate: $rate messages/second"
```

Monitor systemd-netlogd performance:

```bash
# CPU and memory usage
pidstat -r -u -p $(pidof systemd-netlogd) 1

# Network throughput
iftop -f "port 514"
```

### Latency Testing

Measure end-to-end latency:

```python
#!/usr/bin/env python3
import socket
import time
import re

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 514))
sock.settimeout(5)

print("Send a test message now...")

try:
    data, addr = sock.recvfrom(4096)
    recv_time = time.time()
    msg = data.decode('utf-8')

    # Extract timestamp from message
    match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)', msg)
    if match:
        # Parse and calculate latency
        # (Note: Assumes synchronized clocks)
        print(f"Received at: {recv_time}")
        print(f"Message: {msg}")
except socket.timeout:
    print("No message received within timeout")
```

## Continuous Integration

### CI Pipeline

Our CI runs on every commit:

```yaml
# .github/workflows/ci.yml
- Build project
- Run unit tests (meson test)
- Start systemd-netlogd service
- Verify service status
```

### Running CI Locally

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y \
    python3-sphinx ninja-build meson \
    glib-2.0-dev libudev-dev libsystemd-dev \
    clang gperf libcap-dev build-essential \
    libcmocka-dev

# Build
make

# Run tests
meson test -C build -v

# Install
sudo make install

# Create user
sudo useradd -r -d / -s /usr/sbin/nologin \
    -g systemd-journal systemd-journal-netlog

# Start service
sudo systemctl daemon-reload
sudo systemctl start systemd-netlogd

# Check status
sudo systemctl status systemd-netlogd
```

## Test Coverage Goals

### Current Coverage

- ✓ Protocol formatting (RFC 3339 timestamps)
- ✓ String table conversions
- ✓ Build and integration

### Gaps (Future Work)

- ⚠ Configuration parsing
- ⚠ Network protocol compliance (RFC 5424 full validation)
- ⚠ TLS/DTLS handshake
- ⚠ Error handling edge cases
- ⚠ Journal filtering logic
- ⚠ Cursor persistence

### Adding Coverage

To add test coverage:

1. Identify untested code paths
2. Write unit test in `tests/test-<module>.c`
3. Add test to `tests/meson.build`
4. Run and verify: `meson test -C build -v`
5. Submit PR with tests

## Troubleshooting Tests

### Test Failures

```bash
# View detailed test log
cat build/meson-logs/testlog.txt

# Run failing test with GDB
gdb --args build/tests/test-protocol

# Run with valgrind
valgrind --leak-check=full build/tests/test-protocol
```

### Common Issues

**Issue: cmocka not found**
```bash
# Install cmocka
sudo dnf install libcmocka-devel  # Fedora
sudo apt install libcmocka-dev    # Debian/Ubuntu
```

**Issue: Tests time out**
```bash
# Increase timeout
meson test -C build -t 10  # 10x default timeout
```

**Issue: Tests pass locally but fail in CI**
- Check for race conditions
- Verify CI environment matches local
- Review CI logs for environment differences

## Resources

- [cmocka Documentation](https://cmocka.org/)
- [Meson Testing](https://mesonbuild.com/Unit-tests.html)
- [RFC 5424 Test Vectors](https://tools.ietf.org/html/rfc5424#section-6.5)
- [systemd Journal Testing](https://www.freedesktop.org/software/systemd/man/systemd-journal-remote.service.html)
