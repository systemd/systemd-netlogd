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

**systemd-netlogd** forwards log messages from the **systemd journal** to remote hosts over the network using the **Syslog protocol** (RFC 5424 and RFC 3164). It supports unicast and multicast destinations with UDP, TCP, TLS (RFC 5425), and DTLS (RFC 6012) transports.

The daemon reads journal entries sequentially and transmits them without buffering or additional disk usage. It leverages ``sd-network`` to start forwarding when the network is up and pause when it goes down. It runs as the dedicated system user ``systemd-journal-netlog`` with minimal privileges.

Options
-------

**-h**, **--help**
   Show help message and exit.

**--version**
   Show package version.

**--cursor=** *CURSOR*
   Start at the specified journal cursor position.

**--save-state** [=FILE]
   Save uploaded cursors to FILE (default: ``/var/lib/systemd-netlogd/state``).

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
``LogFormat=``                enum    ``rfc5424``   Message format: ``rfc5424`` (recommended), ``rfc5425`` (length-prefixed for TLS), ``rfc3164`` (legacy BSD syslog).
``Directory=``                path    *system*      Custom journal directory. Mutually exclusive with ``Namespace=``.
``Namespace=``                string  *default*     Journal namespace filter: specific ID, ``*`` (all namespaces), or ``+ID`` (ID plus default namespace).
``ConnectionRetrySec=``       time    ``30s``       Reconnect delay after connection failure (minimum 1s). See :manpage:`systemd.time(5)`.
``TLSCertificateAuthMode=``   enum    ``deny``      Certificate validation: ``deny`` (strict, reject invalid), ``warn`` (log but continue), ``allow`` (accept all), ``no`` (disable).
``TLSServerCertificate=``     path    *system*      Path to PEM-encoded CA certificate or certificate bundle. Uses system CA store if not specified.
``KeepAlive=``                bool    ``false``     Enable TCP keepalive probes (``SO_KEEPALIVE``). See :manpage:`socket(7)`.
``KeepAliveTimeSec=``         sec     ``7200``      Seconds of idle time before sending keepalive probes (``TCP_KEEPIDLE``). Only with ``KeepAlive=yes``.
``KeepAliveIntervalSec=``     sec     ``75``        Interval between keepalive probes (``TCP_KEEPINTVL``). Only with ``KeepAlive=yes``.
``KeepAliveProbes=``          int     ``9``         Number of unacknowledged probes before closing (``TCP_KEEPCNT``). Only with ``KeepAlive=yes``.
``SendBuffer=``               size    *system*      Socket send buffer size (``SO_SNDBUF``). Accepts K/M/G suffixes.
``NoDelay=``                  bool    ``false``     Disable Nagle's algorithm (``TCP_NODELAY``). See :manpage:`tcp(7)`.
``StructuredData=``           string  –             Static structured data for all messages. Format: ``[SD-ID@PEN field="value" ...]``.
``UseSysLogStructuredData=``  bool    ``false``     Extract and use ``SYSLOG_STRUCTURED_DATA`` field from journal entries.
``UseSysLogMsgId=``           bool    ``false``     Extract and use ``SYSLOG_MSGID`` field from journal entries.
``ExcludeSyslogFacility=``    list    –             Space-separated list of facilities to exclude (e.g., ``auth authpriv``).
``ExcludeSyslogLevel=``       list    –             Space-separated list of log levels to exclude (e.g., ``debug info``).
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

Unicast UDP (RFC 3164)
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   LogFormat=rfc3164

TLS with Certificate Validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=logs.example.com:6514
   Protocol=tls
   LogFormat=rfc5425
   TLSCertificateAuthMode=deny
   TLSServerCertificate=/etc/pki/tls/certs/ca-bundle.crt
   KeepAlive=yes
   NoDelay=yes
   ExcludeSyslogFacility=auth authpriv

DTLS
^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:4433
   Protocol=dtls
   TLSCertificateAuthMode=warn

TCP with Filtering
^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   Protocol=tcp
   ExcludeSyslogFacility=auth authpriv
   ExcludeSyslogLevel=debug

Structured Data
^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   LogFormat=rfc5424
   StructuredData=[app@12345 env="production"]
   UseSysLogStructuredData=yes
   UseSysLogMsgId=yes

Journal Namespaces
^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.1.100:514
   Protocol=tcp
   Namespace=*

Signals
-------

**SIGTERM**, **SIGINT**
   Graceful shutdown. Closes connections, saves cursor state, and exits.

**SIGUSR1**
   Toggle debug log level for troubleshooting.

**SIGUSR2**
   Reserved for future use.

Environment Variables
---------------------

**SYSTEMD_LOG_LEVEL**
   Set log level: ``debug``, ``info``, ``notice``, ``warning``, ``err``, ``crit``, ``alert``, ``emerg``.

**SYSTEMD_LOG_TARGET**
   Log destination: ``journal``, ``console``, ``journal+console``, ``kmsg``, ``syslog``.

Exit Status
-----------

**0**
   Success.

**Non-zero**
   Failure. Check ``journalctl -u systemd-netlogd`` for details.

Files
-----

**/etc/systemd/netlogd.conf**
   Main configuration file.

**/etc/systemd/netlogd.conf.d/\*.conf**
   Drop-in configuration snippets.

**/lib/systemd/system/systemd-netlogd.service**
   Systemd service unit file.

**/var/lib/systemd-netlogd/state**
   Persistent cursor state file.

**/usr/lib/systemd/systemd-netlogd**
   Main daemon binary.

See Also
--------

:manpage:`systemd-journald.service(8)`, :manpage:`journalctl(1)`, :manpage:`systemd-journal-remote.service(8)`, :manpage:`systemd.socket(5)`, :manpage:`systemd.time(5)`, :manpage:`socket(7)`, :manpage:`tcp(7)`

`RFC 5424 <https://tools.ietf.org/html/rfc5424>`_ (The Syslog Protocol),
`RFC 3164 <https://tools.ietf.org/html/rfc3164>`_ (BSD Syslog Protocol),
`RFC 5425 <https://tools.ietf.org/html/rfc5425>`_ (TLS Transport Mapping for Syslog),
`RFC 3339 <https://tools.ietf.org/html/rfc3339>`_ (Date and Time on the Internet),
`RFC 6012 <https://tools.ietf.org/html/rfc6012>`_ (DTLS Transport Mapping for Syslog)

Author
------

Susant Sahani <ssahani@gmail.com>

Reporting Bugs
--------------

Report bugs at https://github.com/systemd/systemd-netlogd/issues
