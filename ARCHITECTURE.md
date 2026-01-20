# systemd-netlogd Architecture

This document describes the internal architecture and design decisions of systemd-netlogd.

## Table of Contents

- [Overview](#overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Key Components](#key-components)
- [Network Protocols](#network-protocols)
- [State Management](#state-management)
- [Security Model](#security-model)
- [Performance Considerations](#performance-considerations)

## Overview

systemd-netlogd is a network logging daemon that reads from the systemd journal and forwards log entries to remote syslog servers. It operates as a single-threaded, event-driven daemon using the systemd sd-event event loop.

### Design Principles

1. **Zero Buffering**: Reads journal sequentially without local caching
2. **Network Aware**: Automatically handles network state changes
3. **Resource Efficient**: Minimal memory and CPU footprint
4. **Fault Tolerant**: Automatic reconnection with cursor persistence
5. **Protocol Compliance**: Strict adherence to RFC specifications

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     systemd-netlogd                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │   Manager    │◄────►│  Event Loop  │                    │
│  │              │      │  (sd-event)  │                    │
│  └──────┬───────┘      └──────────────┘                    │
│         │                                                   │
│         ├──────► Journal Monitor (sd-journal)              │
│         │         - Reads journal entries                  │
│         │         - Cursor persistence                     │
│         │                                                   │
│         ├──────► Network Monitor (sd-network)              │
│         │         - Detects network state changes          │
│         │         - Triggers connect/disconnect            │
│         │                                                   │
│         ├──────► Protocol Layer                            │
│         │         ├─► RFC 5424 Formatter                   │
│         │         ├─► RFC 3339 Formatter                   │
│         │         └─► RFC 5425 Formatter                   │
│         │                                                   │
│         └──────► Transport Layer                           │
│                   ├─► UDP Socket                           │
│                   ├─► TCP Socket                           │
│                   ├─► TLS Manager (OpenSSL)                │
│                   └─► DTLS Manager (OpenSSL)               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
   systemd Journal              Remote Syslog Server
```

## Data Flow

### Journal Entry to Network Packet

```
1. Journal Event
   │
   ├─► sd_journal_next() - Read next entry
   │
   ├─► manager_read_journal_input()
   │    ├─► Parse journal fields (MESSAGE, PRIORITY, FACILITY, etc.)
   │    ├─► Apply facility/level filters
   │    └─► Extract timestamp
   │
   ├─► manager_push_to_network()
   │    ├─► Select formatter (RFC 5424/3339)
   │    ├─► format_rfc5424() or format_rfc3339()
   │    │    ├─► Build priority field: <PRI> = (facility * 8) + severity
   │    │    ├─► Format timestamp (RFC 3339)
   │    │    ├─► Add hostname, identifier, pid
   │    │    ├─► Add structured data (if configured)
   │    │    └─► Append message
   │    └─► protocol_send()
   │
   └─► Transport Layer
        ├─► UDP: sendmsg() via network_send()
        ├─► TCP: send() via network_send()
        ├─► TLS: SSL_write() via tls_stream_writev()
        └─► DTLS: SSL_write() via dtls_datagram_writev()
```

### Connection State Machine

```
          ┌──────────────┐
          │ DISCONNECTED │
          └───────┬──────┘
                  │
          Network Up Event
                  │
                  ▼
          ┌──────────────┐
     ┌───►│  RESOLVING   │
     │    └───────┬──────┘
     │            │
     │       DNS Success
     │            │
     │            ▼
     │    ┌──────────────┐
     │    │  CONNECTING  │────Error────┐
     │    └───────┬──────┘             │
     │            │                    │
     │      Connection OK              │
     │            │                    │
     │            ▼                    │
     │    ┌──────────────┐             │
     │    │  CONNECTED   │             │
     │    └───────┬──────┘             │
     │            │                    │
     │      Network Down               │
     │      or Error                   │
     │            │                    │
     │            ▼                    │
     │    ┌──────────────┐             │
     └────┤ RETRY TIMER  │◄────────────┘
          └──────────────┘
           (ConnectionRetrySec)
```

## Key Components

### Manager (`netlog-manager.c`)

The central component that orchestrates all operations.

**Responsibilities:**
- Event loop management
- Journal monitoring
- Network state monitoring
- Connection lifecycle
- Configuration management
- Cursor state persistence

**Key Functions:**
- `manager_new()`: Initialize manager with default configuration
- `manager_connect()`: Establish connection to remote server
- `manager_disconnect()`: Clean shutdown of connections
- `manager_read_journal_input()`: Process journal entries
- `manager_push_to_network()`: Send formatted log to network

**State:**
```c
struct Manager {
        /* Event loop */
        sd_event *event;
        sd_event_source *event_journal_input;
        sd_event_source *event_retry;

        /* Journal */
        sd_journal *journal;
        char *last_cursor;

        /* Network */
        sd_network_monitor *network_monitor;
        sd_resolve *resolve;
        int socket;

        /* Transport managers */
        TLSManager *tls;
        DTLSManager *dtls;

        /* Configuration */
        SysLogTransmissionProtocol protocol;
        SysLogTransmissionLogFormat log_format;
        SocketAddress address;

        /* Filtering */
        uint32_t excluded_syslog_facilities;
        uint8_t excluded_syslog_levels;
};
```

### Protocol Layer (`netlog-protocol.c`)

Formats log entries according to syslog RFCs.

**RFC 5424 Format:**
```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

Example:
```
<34>1 2024-01-20T10:30:15.123456+00:00 hostname myapp 1234 LOGIN001 [auth@12345] User logged in
```

**RFC 3339 Format (Legacy):**
```
<PRI>TIMESTAMP HOSTNAME APP-NAME[PROCID]: MSG
```

Example:
```
<34>2024-01-20T10:30:15.123456+00:00 hostname myapp[1234]: User logged in
```

**RFC 5425 Format (Length-Prefixed for TCP/TLS):**
```
<LENGTH> <RFC5424-MESSAGE>
```

Example:
```
123 <34>1 2024-01-20T10:30:15...
```

### TLS/DTLS Managers

**TLS Manager (`netlog-tls.c`):**
- Uses OpenSSL for TLS stream connections
- TCP socket + SSL_connect()
- Certificate validation modes: none, allow, warn, deny
- Automatic reconnection on errors

**DTLS Manager (`netlog-dtls.c`):**
- Uses OpenSSL for DTLS datagram connections
- UDP socket + BIO_new_dgram()
- Same certificate validation as TLS
- 3-second timeout for handshake

**Common SSL Operations (`netlog-ssl.c`):**
- Certificate chain validation
- `ssl_verify_certificate_validity()`: Custom verification callback
- Supports both custom CA certificates and system defaults

### Network Layer (`netlog-network.c`)

Handles UDP/TCP socket operations.

**UDP:**
- Connectionless datagram
- Multicast support
- No delivery guarantee
- Lowest overhead

**TCP:**
- Connection-oriented stream
- Reliable delivery
- Optional keepalive
- Optional TCP_NODELAY (disable Nagle)

**Socket Options:**
```c
SO_SNDBUF        - Send buffer size
SO_KEEPALIVE     - TCP keepalive
TCP_KEEPCNT      - Keepalive probe count
TCP_KEEPIDLE     - Keepalive idle time
TCP_KEEPINTVL    - Keepalive interval
TCP_NODELAY      - Disable Nagle algorithm
```

## Network Protocols

### Protocol Selection Matrix

| Protocol | Transport | Encryption | Use Case |
|----------|-----------|------------|----------|
| UDP | Datagram | None | High-volume, local network |
| TCP | Stream | None | Reliable delivery needed |
| TLS | Stream | Yes | Secure, over internet |
| DTLS | Datagram | Yes | Secure, low-latency |

### Message Framing

**UDP/DTLS:**
- Each datagram = one log message
- No framing needed
- MTU considerations (~1500 bytes)

**TCP (RFC 5424 with newline):**
```
<message1>\n
<message2>\n
```

**TLS (RFC 5425 with length prefix):**
```
123 <message1>
456 <message2>
```

## State Management

### Cursor Persistence

The cursor tracks the last successfully forwarded journal entry.

**State File:** `/var/lib/systemd-netlogd/state`

**Format:**
```ini
# This is private data. Do not parse.
LAST_CURSOR=s=abc123...
```

**Lifecycle:**
1. Load cursor on startup (`load_cursor_state()`)
2. Seek to cursor position (`sd_journal_seek_cursor()`)
3. Update cursor after each successful send
4. Persist to disk periodically (`update_cursor_state()`)

**Recovery:**
- If cursor invalid: Start from journal beginning
- If cursor missing: Start from current position
- On network failure: Cursor not updated, replay on reconnect

### Configuration Reload

systemd-netlogd supports runtime configuration reload:

```bash
sudo systemctl reload systemd-netlogd
```

**Reloadable settings:**
- Network address and protocol
- Log format
- Filters (facilities, levels)
- TLS certificate paths
- Connection retry interval

**Non-reloadable settings:**
- Journal namespace
- State file path

## Security Model

### Privilege Dropping

Runs as unprivileged user `systemd-journal-netlog`:
- No root privileges required
- Limited file system access
- Restricted network capabilities

### Capability Restrictions

systemd service unit applies:
```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
```

### TLS Certificate Validation

**Modes:**

1. **deny** (default): Reject on validation failure
   - Strict verification
   - Recommended for production

2. **warn**: Log warning but continue
   - Development/testing
   - Audit certificate issues

3. **allow**: Accept all certificates
   - Self-signed certificates
   - Use with caution

4. **no**: Disable verification
   - Not recommended

**Validation Process:**
```c
ssl_verify_certificate_validity()
├─► Check certificate expiration
├─► Verify certificate chain
├─► Check certificate purpose
└─► Log result based on auth_mode
```

### Sensitive Data Filtering

Exclude sensitive facilities by default:
```ini
ExcludeSyslogFacility=auth authpriv
```

Facilities that may contain credentials:
- `auth` (4): Authentication/authorization
- `authpriv` (10): Private authentication

## Performance Considerations

### Memory Efficiency

- **Zero buffering**: No message queues or buffers
- **RAII pattern**: Automatic resource cleanup via `_cleanup_` macros
- **No malloc loops**: Pre-allocated structures where possible

### CPU Efficiency

- **Event-driven**: Single-threaded, no polling
- **Rate limiting**: Default 10 messages per 10 seconds
- **Efficient parsing**: Direct field access via `sd_journal_enumerate_data()`

### Network Efficiency

**UDP:**
- Single sendmsg() call per message
- No connection overhead

**TCP:**
- Nagle algorithm (unless NoDelay=true)
- Send buffer tuning via SO_SNDBUF

**TLS:**
- Connection reuse (persistent)
- Session resumption supported

### Scalability Limits

| Metric | Limit | Notes |
|--------|-------|-------|
| Messages/sec | ~10,000 | With rate limiting disabled |
| Concurrent connections | 1 | Single destination only |
| Message size | ~64KB | Protocol limit |
| Journal lag | Unbounded | Depends on network speed |

## Error Handling Strategy

### Connection Errors

1. **Transient errors** (-EAGAIN, -EINPROGRESS):
   - Retry immediately
   - No cursor update

2. **Fatal errors** (-EPIPE, -ECONNRESET):
   - Close connection
   - Schedule reconnect after ConnectionRetrySec
   - Cursor remains at last successful position

3. **DNS resolution failures**:
   - Retry with exponential backoff
   - Fall back to next host (future feature)

### Journal Errors

1. **-EBADMSG** (Malformed entry):
   - Log and skip entry
   - Continue to next

2. **-EADDRNOTAVAIL** (Journal rotated):
   - Reopen journal
   - Continue from cursor

## Future Architecture Considerations

### Potential Enhancements

1. **Multi-destination support**
   - Array of destinations
   - Load balancing
   - Failover logic

2. **Compression**
   - gzip compression for large messages
   - Reduces bandwidth usage

3. **Message queuing**
   - Optional disk buffering
   - Survive extended outages

4. **Metrics export**
   - Prometheus endpoint
   - Operational visibility

5. **Content filtering**
   - Regex-based message filtering
   - Tag-based routing

## References

- [RFC 5424](https://tools.ietf.org/html/rfc5424) - The Syslog Protocol
- [RFC 5425](https://tools.ietf.org/html/rfc5425) - Transport Layer Security (TLS) Transport Mapping for Syslog
- [RFC 3339](https://tools.ietf.org/html/rfc3339) - Date and Time on the Internet: Timestamps
- [RFC 6012](https://tools.ietf.org/html/rfc6012) - Datagram Transport Layer Security (DTLS) Transport Mapping for Syslog
- [systemd Journal](https://www.freedesktop.org/software/systemd/man/sd-journal.html)
- [systemd Event Loop](https://www.freedesktop.org/software/systemd/man/sd-event.html)
