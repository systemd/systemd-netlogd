:orphan:

systemd-netlogd(8)
==================

.. contents::
   :depth: 2
   :local:
   :backlinks: none

Name
----

**systemd-netlogd** - Forward systemd journal messages to remote hosts via Syslog

Synopsis
--------

::

    systemd-netlogd [OPTIONS...]

Description
-----------

**systemd-netlogd** is a lightweight, network-aware daemon for forwarding log messages from the **systemd journal** to remote hosts over the network using the **Syslog protocol** (RFC 5424 and RFC 3339). It supports unicast and multicast destinations, ensuring efficient log aggregation in distributed environments.

Key features:

- **Efficient forwarding**: Reads journal entries sequentially and transmits them one-by-one without buffering or additional disk usage.
- **Network integration**: Leverages ``sd-network`` to start forwarding when the network is up and pause when it's down.
- **Secure transports**: Supports UDP (default), TCP, TLS, and DTLS (RFC 6012 for datagram security).
- **Flexible output**: Formats logs as RFC 5424 (default), RFC 5425 (length-prefixed for TLS), or RFC 3339.
- **Isolation**: Runs as the dedicated system user ``systemd-journal-netlog`` with minimal privileges.
- **Filtering**: Exclude specific syslog facilities or levels; target specific journal namespaces.
- **Fault tolerant**: Automatic reconnection with cursor persistence ensures no message loss.

This daemon is ideal for edge devices, servers, or cloud setups requiring centralized logging with minimal resource impact.

**Typical Use Cases:**

- Centralized logging for distributed systems
- Cloud log aggregation (Papertrail, Loggly, etc.)
- Security event monitoring and SIEM integration
- Compliance and audit log forwarding
- Edge device telemetry collection

Installation
------------

Use your distribution's package manager:

- **Ubuntu/Debian**: ``sudo apt install systemd-netlogd``
- **Fedora/RHEL**: Available via COPR repositories (search for ``systemd-netlogd``).
- **Arch Linux**: Build from AUR (``systemd-netlogd-git``).

For building from source, see the `GitHub repository <https://github.com/systemd/systemd-netlogd>`_.

User Creation
-------------

The daemon requires a dedicated system user. Create it manually:

.. code-block:: console

   sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog

Or via ``sysusers.d`` (preferred):

.. code-block:: ini

   # /etc/sysusers.d/systemd-netlogd.conf
   # Type   Name                    ID   GECOS   Home directory  Shell
   u       systemd-journal-netlog  -    -       /               /bin/nologin

Apply with:

.. code-block:: console

   sudo systemd-sysusers

Running the Service
-------------------

Enable and start via systemd:

.. code-block:: console

   sudo systemctl daemon-reload
   sudo systemctl enable --now systemd-netlogd.service

- **Logs**: ``journalctl -u systemd-netlogd.service``
- **Manual invocation**: ``sudo systemd-netlogd`` (for testing).

Configuration
-------------

Read from ``/etc/systemd/netlogd.conf`` and drop-ins in ``/etc/systemd/netlogd.conf.d/*.conf`` (INI format).

Options are in the ``[Network]`` section. Reload changes:

.. code-block:: console

   sudo systemctl reload systemd-netlogd.service

[Network] Section Options
-------------------------

.. tabularcolumns:: |p{3cm}|p{1.5cm}|p{1.5cm}|p{7cm}|

============================  ======  ============  ================================================================================================
Option                        Type    Default       Description
============================  ======  ============  ================================================================================================
``Address=``                  string  *(required)*  Destination (unicast ``IP:PORT`` or multicast ``GROUP:PORT``). See :manpage:`systemd.socket(5)`.
``Protocol=``                 enum    ``udp``       Transport protocol: ``udp``, ``tcp``, ``tls``, ``dtls``.
``LogFormat=``                enum    ``rfc5424``   Message format: ``rfc5424`` (recommended), ``rfc5425`` (length-prefixed for TLS), ``rfc3339`` (legacy BSD syslog).
``Directory=``                path    *system*      Custom journal directory. Mutually exclusive with ``Namespace=``.
``Namespace=``                string  *default*     Journal namespace filter: specific ID, ``*`` (all namespaces), or ``+ID`` (ID plus default namespace).
``ConnectionRetrySec=``       time    ``30s``       Reconnect delay after connection failure (minimum 1s). See :manpage:`systemd.time(5)`.
``TLSCertificateAuthMode=``   enum    ``deny``      Certificate validation: ``deny`` (strict, reject invalid), ``warn`` (log but continue), ``allow`` (accept all), ``no`` (disable).
``TLSServerCertificate=``     path    *system*      Path to PEM-encoded CA certificate or certificate bundle. Uses system CA store if not specified.
``KeepAlive=``                bool    ``false``     Enable TCP keepalive probes (``SO_KEEPALIVE``). Detects dead connections. See :manpage:`socket(7)`.
``KeepAliveTimeSec=``         sec     ``7200``      Seconds of idle time before sending keepalive probes (``TCP_KEEPIDLE``). Only with ``KeepAlive=yes``.
``KeepAliveIntervalSec=``     sec     ``75``        Interval between keepalive probes (``TCP_KEEPINTVL``). Only with ``KeepAlive=yes``.
``KeepAliveProbes=``          int     ``9``         Number of unacknowledged probes before closing (``TCP_KEEPCNT``). Only with ``KeepAlive=yes``.
``SendBuffer=``               size    *system*      Socket send buffer size (``SO_SNDBUF``). Accepts K/M/G suffixes. Larger buffers improve burst handling.
``NoDelay=``                  bool    ``false``     Disable Nagle's algorithm (``TCP_NODELAY``). Reduces latency but increases packet count. See :manpage:`tcp(7)`.
``StructuredData=``           string  –             Static structured data appended to all messages. Format: ``[SD-ID@PEN field="value" ...]``. Useful for cloud services.
``UseSysLogStructuredData=``  bool    ``false``     Extract and use ``SYSLOG_STRUCTURED_DATA`` field from journal entries.
``UseSysLogMsgId=``           bool    ``false``     Extract and use ``SYSLOG_MSGID`` field from journal entries for message identification.
``ExcludeSyslogFacility=``    list    –             Space-separated list of facilities to exclude from forwarding (e.g., ``auth authpriv`` to prevent credential leaks).
``ExcludeSyslogLevel=``       list    –             Space-separated list of log levels to exclude (e.g., ``debug info`` to reduce volume).
============================  ======  ============  ================================================================================================

**Facilities**: ``kern``, ``user``, ``mail``, ``daemon``, ``auth``, ``syslog``, ``lpr``, ``news``, ``uucp``, ``cron``, ``authpriv``, ``ftp``, ``ntp``, ``security``, ``console``, ``solaris-cron``, ``local0``–``local7``.

**Levels**: ``emerg``, ``alert``, ``crit``, ``err``, ``warning``, ``notice``, ``info``, ``debug``.

Examples
--------

UDP Multicast
^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=239.0.0.1:6000

Unicast UDP (RFC 3339)
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   LogFormat=rfc3339

Custom Structured Data
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]

TLS
^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   Protocol=tls
   LogFormat=rfc5425
   TLSCertificateAuthMode=deny

DTLS
^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:4433
   Protocol=dtls
   TLSCertificateAuthMode=warn

Extract Journal Metadata
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   LogFormat=rfc5424
   UseSysLogStructuredData=yes
   UseSysLogMsgId=yes

TCP with Filtering
^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   Protocol=tcp
   ExcludeSyslogFacility=auth authpriv
   ExcludeSyslogLevel=debug

Production TLS Setup
^^^^^^^^^^^^^^^^^^^^

Secure configuration for production use with strict certificate validation:

.. code-block:: ini

   [Network]
   Address=logs.example.com:6514
   Protocol=tls
   LogFormat=rfc5425
   TLSCertificateAuthMode=deny
   TLSServerCertificate=/etc/pki/tls/certs/ca-bundle.crt
   KeepAlive=yes
   NoDelay=yes
   ConnectionRetrySec=15
   ExcludeSyslogFacility=auth authpriv

High-Performance UDP
^^^^^^^^^^^^^^^^^^^^

Optimized for high message volumes on local networks:

.. code-block:: ini

   [Network]
   Address=192.168.1.100:514
   Protocol=udp
   LogFormat=rfc5424
   ExcludeSyslogLevel=debug
   # Reduce retry interval for fast fail-over
   ConnectionRetrySec=5

Cloud Service - Papertrail
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Configuration for Papertrail cloud logging service:

.. code-block:: ini

   [Network]
   Address=logs7.papertrailapp.com:12345
   Protocol=tls
   LogFormat=rfc5424
   TLSCertificateAuthMode=deny
   KeepAlive=yes
   NoDelay=yes

Cloud Service - Loggly
^^^^^^^^^^^^^^^^^^^^^^^

Configuration for Loggly with customer token in structured data:

.. code-block:: ini

   [Network]
   Address=logs-01.loggly.com:6514
   Protocol=tls
   LogFormat=rfc5424
   StructuredData=[YOUR-CUSTOMER-TOKEN@41058]
   TLSCertificateAuthMode=deny
   KeepAlive=yes

Multiple Namespaces
^^^^^^^^^^^^^^^^^^^

Forward logs from all journal namespaces:

.. code-block:: ini

   [Network]
   Address=192.168.1.100:514
   Protocol=tcp
   Namespace=*
   LogFormat=rfc5424

Using Structured Data and Message IDs
-------------------------------------

Tag journal entries for extraction:

.. code-block:: c

   #include <systemd/sd-journal.h>

   int main(void) {
       sd_journal_send(
           "MESSAGE=%s", "Message to process",
           "PRIORITY=%i", 4,  // warning
           "SYSLOG_FACILITY=%i", 1,  // user
           "SYSLOG_MSGID=%s", "1011",
           "SYSLOG_STRUCTURED_DATA=%s", R"([exampleSDID@32473 iut="3" eventSource="Application"])",
           NULL);
       return 0;
   }

Compile: ``gcc example.c -lsystemd``.

Security
--------

**systemd-netlogd** runs with minimal privileges as the ``systemd-journal-netlog`` system user.

Privilege Separation
^^^^^^^^^^^^^^^^^^^^

The daemon uses systemd's security features:

- **User isolation**: Runs as dedicated ``systemd-journal-netlog`` user (not root)
- **Capability restrictions**: Limited to ``CAP_NET_BIND_SERVICE`` for privileged ports
- **No new privileges**: ``NoNewPrivileges=yes`` prevents privilege escalation
- **Filesystem protection**: ``ProtectSystem=strict``, ``ProtectHome=yes``
- **Private temporary files**: ``PrivateTmp=yes``

Best Practices
^^^^^^^^^^^^^^

1. **Use TLS for remote logging**: Always use ``Protocol=tls`` when forwarding over untrusted networks.

2. **Filter sensitive data**: Exclude authentication logs that may contain credentials:

   .. code-block:: ini

      ExcludeSyslogFacility=auth authpriv

3. **Strict certificate validation**: Use ``TLSCertificateAuthMode=deny`` in production:

   .. code-block:: ini

      TLSCertificateAuthMode=deny
      TLSServerCertificate=/path/to/ca.pem

4. **Secure the remote server**: Protect the destination syslog server with firewall rules and access controls.

5. **Audit service security**: Use systemd-analyze to review security posture:

   .. code-block:: console

      sudo systemd-analyze security systemd-netlogd.service

Performance Tuning
------------------

Protocol Selection
^^^^^^^^^^^^^^^^^^

Choose the appropriate protocol for your use case:

- **UDP**: Lowest overhead, use for high-volume logging on local networks. No delivery guarantee.
- **TCP**: Reliable delivery with connection overhead. Use when message loss is unacceptable.
- **TLS**: Encrypted TCP with highest overhead. Use for internet/untrusted networks.
- **DTLS**: Encrypted UDP with moderate overhead. Use for low-latency encrypted datagrams.

Optimization Techniques
^^^^^^^^^^^^^^^^^^^^^^^

1. **Disable Nagle's algorithm** for low-latency forwarding:

   .. code-block:: ini

      Protocol=tcp
      NoDelay=yes

2. **Increase send buffer** for burst traffic:

   .. code-block:: ini

      SendBuffer=262144  # 256 KB

3. **Filter verbose logs** to reduce volume:

   .. code-block:: ini

      ExcludeSyslogLevel=debug info

4. **Reduce retry interval** for faster failover:

   .. code-block:: ini

      ConnectionRetrySec=5

5. **Use UDP for extreme volumes**: UDP has minimal overhead but no delivery guarantee.

Rate Limiting
^^^^^^^^^^^^^

systemd-netlogd has built-in rate limiting (10 messages per 10 seconds by default) to prevent flooding. If the journal generates messages faster than the network can forward, backpressure occurs and journal reading pauses.

Monitor performance with:

.. code-block:: console

   journalctl -u systemd-netlogd -n 100

Signals
-------

**SIGTERM**, **SIGINT**
   Graceful shutdown. Closes connections, saves cursor state, and exits cleanly.

**SIGUSR1**
   Increase log level to debug for troubleshooting. Send again to revert.

**SIGUSR2**
   Reserved for future use.

Example:

.. code-block:: console

   # Enable debug logging temporarily
   sudo kill -SIGUSR1 $(pidof systemd-netlogd)

   # View debug output
   journalctl -u systemd-netlogd -f

Environment Variables
---------------------

**SYSTEMD_LOG_LEVEL**
   Set log level: ``debug``, ``info``, ``notice``, ``warning``, ``err``, ``crit``, ``alert``, ``emerg``.

   Override via systemd service:

   .. code-block:: console

      sudo systemctl edit systemd-netlogd

   Add:

   .. code-block:: ini

      [Service]
      Environment=SYSTEMD_LOG_LEVEL=debug

**SYSTEMD_LOG_TARGET**
   Log destination: ``journal``, ``console``, ``journal+console``, ``kmsg``, ``syslog``.

   Example:

   .. code-block:: ini

      [Service]
      Environment=SYSTEMD_LOG_TARGET=journal+console

Exit Status
-----------

**0**
   Success. Daemon started and handled shutdown signal cleanly.

**Non-zero**
   Failure. Check ``journalctl -u systemd-netlogd`` for error messages.

Common exit conditions:

- Configuration file parse errors
- Unable to open journal
- Network initialization failures
- Permission denied (user/group issues)

State Persistence
-----------------

The daemon maintains state in ``/var/lib/systemd-netlogd/state`` to track the last successfully forwarded journal entry (cursor). This ensures:

- **No message loss** on daemon restart
- **Replay prevention** - doesn't re-send old messages
- **Resume from last position** after network outages

The state file format:

.. code-block:: ini

   # This is private data. Do not parse.
   LAST_CURSOR=s=abc123def456...

To start from scratch:

.. code-block:: console

   sudo systemctl stop systemd-netlogd
   sudo rm /var/lib/systemd-netlogd/state
   sudo systemctl start systemd-netlogd

Files
-----

**/etc/systemd/netlogd.conf**
   Main configuration file. See ``[Network]`` section options above.

**/etc/systemd/netlogd.conf.d/\*.conf**
   Drop-in configuration snippets. Processed in lexicographic order. Use for environment-specific overrides.

**/lib/systemd/system/systemd-netlogd.service**
   Systemd service unit file. Contains security hardening directives.

**/var/lib/systemd-netlogd/state**
   Persistent state file storing journal cursor position. Ensures no message loss across restarts.

**/usr/lib/systemd/systemd-netlogd**
   Main daemon binary.

Troubleshooting
---------------

No Logs Being Forwarded
^^^^^^^^^^^^^^^^^^^^^^^^

1. **Check service status**:

   .. code-block:: console

      sudo systemctl status systemd-netlogd
      journalctl -u systemd-netlogd -n 50

2. **Verify network connectivity**:

   .. code-block:: console

      nc -vz remote-server 514    # TCP
      nc -u -vz remote-server 514 # UDP

3. **Check configuration**:

   .. code-block:: console

      cat /etc/systemd/netlogd.conf

4. **Verify user exists**:

   .. code-block:: console

      id systemd-journal-netlog

TLS/DTLS Connection Failures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Test TLS connectivity manually**:

   .. code-block:: console

      openssl s_client -connect server:6514 -CAfile /path/to/ca.pem

2. **Check certificate validity**:

   .. code-block:: console

      openssl x509 -in /path/to/ca.pem -noout -dates -issuer -subject

3. **Try relaxed validation for testing**:

   .. code-block:: ini

      TLSCertificateAuthMode=warn  # or 'allow' for self-signed certs

4. **View SSL errors**:

   .. code-block:: console

      journalctl -u systemd-netlogd | grep -i ssl

Connection Refused Errors
^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Check firewall** on remote server:

   .. code-block:: console

      # On remote server
      sudo firewall-cmd --list-all
      sudo iptables -L -n | grep 514

2. **Verify remote syslog server is running**:

   .. code-block:: console

      # On remote server
      sudo netstat -tuln | grep 514

3. **Test with netcat** as simple receiver:

   .. code-block:: console

      # Start receiver
      nc -ul 514  # UDP
      nc -l 514   # TCP

4. **Generate test log**:

   .. code-block:: console

      logger -p user.info "Test message from systemd-netlogd"

Performance Issues / Message Lag
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Check network latency**:

   .. code-block:: console

      ping remote-server

2. **Monitor journal lag**:

   .. code-block:: console

      journalctl -u systemd-netlogd | grep "cursor"

3. **Disable rate limiting** (if needed):

   Rate limiting is hardcoded at 10 messages per 10 seconds. For high volumes, consider:

   - Using UDP instead of TCP
   - Filtering debug messages with ``ExcludeSyslogLevel=debug info``
   - Increasing network send buffer with ``SendBuffer=262144``

4. **Check for dropped packets** (UDP only):

   .. code-block:: console

      netstat -su | grep -i drop

Debug Mode
^^^^^^^^^^

Enable verbose logging:

.. code-block:: console

   sudo systemctl edit systemd-netlogd

Add:

.. code-block:: ini

   [Service]
   Environment=SYSTEMD_LOG_LEVEL=debug
   StandardOutput=journal+console

Restart and view output:

.. code-block:: console

   sudo systemctl restart systemd-netlogd
   journalctl -u systemd-netlogd -f

Testing Configuration
^^^^^^^^^^^^^^^^^^^^^

1. **Validate configuration syntax**:

   .. code-block:: console

      sudo systemd-netlogd --test  # If supported

2. **Start receiver** on destination:

   .. code-block:: console

      # Simple UDP receiver
      nc -ul 514

      # Or use socat for more features
      socat UDP4-RECVFROM:514,fork -

3. **Generate test messages**:

   .. code-block:: console

      # Info message
      logger -p user.info "Test info message"

      # Warning message
      logger -p user.warning "Test warning message"

      # With structured data
      systemd-cat -t myapp -p info <<< "Test from systemd-cat"

Notes
-----

- **Zero buffering**: systemd-netlogd reads the journal sequentially without local caching. This minimizes disk usage but means log forwarding speed is limited by network bandwidth.

- **Cursor persistence**: The journal cursor is saved to ``/var/lib/systemd-netlogd/state`` after successful forwarding. This ensures no message loss across daemon restarts or network outages.

- **Automatic reconnection**: The daemon automatically reconnects when network becomes available or after ``ConnectionRetrySec`` delay on connection failures.

- **Rate limiting**: Built-in rate limiting (10 messages per 10 seconds) prevents flooding. If the journal produces messages faster than the network can forward, backpressure occurs.

- **Single destination**: Currently supports forwarding to one destination only. Use rsyslog or syslog-ng as an intermediary for multi-destination forwarding.

- **No client certificates**: TLS/DTLS currently supports server certificate validation only. Client certificate authentication is not supported.

See Also
--------

**System Configuration:**
   :manpage:`systemd.socket(5)`, :manpage:`systemd.time(5)`, :manpage:`systemd.service(5)`, :manpage:`systemd.unit(5)`

**Network and Security:**
   :manpage:`socket(7)`, :manpage:`tcp(7)`, :manpage:`ip(7)`, :manpage:`ssl(7)`

**systemd Components:**
   :manpage:`systemd-journald.service(8)`, :manpage:`journalctl(1)`, :manpage:`systemd-journal-remote.service(8)`, :manpage:`systemd-journal-upload.service(8)`, :manpage:`sd-journal(3)`

**RFCs and Standards:**
   - `RFC 5424 <https://tools.ietf.org/html/rfc5424>`_ - The Syslog Protocol
   - `RFC 5425 <https://tools.ietf.org/html/rfc5425>`_ - Transport Layer Security (TLS) Transport Mapping for Syslog
   - `RFC 3339 <https://tools.ietf.org/html/rfc3339>`_ - Date and Time on the Internet: Timestamps
   - `RFC 6012 <https://tools.ietf.org/html/rfc6012>`_ - Datagram Transport Layer Security (DTLS) Transport Mapping for Syslog

**Project Resources:**
   - GitHub: https://github.com/systemd/systemd-netlogd
   - Documentation: https://github.com/systemd/systemd-netlogd/blob/main/README.md
   - Architecture: https://github.com/systemd/systemd-netlogd/blob/main/ARCHITECTURE.md
   - Contributing: https://github.com/systemd/systemd-netlogd/blob/main/CONTRIBUTING.md
   - Testing: https://github.com/systemd/systemd-netlogd/blob/main/TESTING.md
   - FAQ: https://github.com/systemd/systemd-netlogd/blob/main/FAQ.md

**Related Tools:**
   - rsyslog: https://www.rsyslog.com/
   - syslog-ng: https://www.syslog-ng.com/
   - journalctl: :manpage:`journalctl(1)`

Author
------

Susant Sahani <ssahani@gmail.com>

Contributors: See GitHub commit history at https://github.com/systemd/systemd-netlogd/graphs/contributors

Reporting Bugs
--------------

Report bugs to the GitHub issue tracker:
https://github.com/systemd/systemd-netlogd/issues

Please include:

- systemd-netlogd version (``systemd-netlogd --version``)
- Operating system and version
- Configuration file contents
- Relevant log output from ``journalctl -u systemd-netlogd``
- Steps to reproduce the issue

Colophon
--------

This page is part of the **systemd-netlogd** project (version 1.4.5).

systemd-netlogd is licensed under the GNU Lesser General Public License (LGPL) version 2.1 or later, the same license as systemd.

For license information, see the LICENSE file in the source distribution or visit:
https://www.gnu.org/licenses/lgpl-2.1.html
