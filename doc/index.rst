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
- **Isolation**: Runs as the dedicated system user ``systemd-journal-netlog``.
- **Filtering**: Exclude specific syslog facilities or levels; target journal namespaces.

This daemon is ideal for edge devices, servers, or cloud setups requiring centralized logging with minimal resource impact.

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

+--------------------+----------+-------------+-------------------------------------------------------------+
| Option             | Type     | Default     | Description                                                  |
+====================+==========+=============+=============================================================+
| ``Address=``       | string   | *(required)*| Destination (unicast ``IP:PORT`` or multicast ``GROUP:PORT``). See :manpage:`systemd.socket(5)`. |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``Protocol=``      | enum     | ``udp``     | ``udp``, ``tcp``, ``tls``, ``dtls``.                        |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``LogFormat=``     | enum     | ``rfc5424``| ``rfc5424``, ``rfc5425`` (TLS-friendly), ``rfc3339``.       |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``Directory=``     | path     | *system*    | Custom journal directory.                                    |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``Namespace=``     | string   | *default*   | Filter: ID, ``*`` (all), ``+ID`` (ID + default).            |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``ConnectionRetrySec=`` | time | ``30s`` | Reconnect delay (≥1s). See :manpage:`systemd.time(5)`.     |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``TLSCertificateAuthMode=`` | enum | ``no`` | ``no``, ``allow``, ``deny``, ``warn`` (validation modes). |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``TLSServerCertificate=`` | path | – | PEM CA/server cert for validation.                         |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``KeepAlive=``     | bool     | ``false``   | Enable TCP keepalives (``SO_KEEPALIVE``). See :manpage:`socket(7)`. |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``KeepAliveTimeSec=`` | sec | ``7200`` | Idle before probes (``TCP_KEEPIDLE``).                      |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``KeepAliveIntervalSec=`` | sec | ``75`` | Probe interval (``TCP_KEEPINTVL``).                         |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``KeepAliveProbes=`` | int  | ``9``     | Probes before close (``TCP_KEEPCNT``).                      |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``SendBuffer=``    | size     | *system*    | Send buffer (``SO_SNDBUF``; K/M/G suffixes).                |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``NoDelay=``       | bool     | ``false``   | Disable Nagle (``TCP_NODELAY``). See :manpage:`tcp(7)`.     |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``StructuredData=``| string   | –           | Fixed SD-ID (e.g., for Loggly).                              |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``UseSysLogStructuredData=`` | bool | ``false`` | Extract ``SYSLOG_STRUCTURED_DATA`` from journal.           |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``UseSysLogMsgId=``| bool     | ``false``   | Extract ``SYSLOG_MSGID`` from journal.                      |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``ExcludeSyslogFacility=`` | list | –     | Skip facilities (e.g., ``auth,authpriv``).                  |
+--------------------+----------+-------------+-------------------------------------------------------------+
| ``ExcludeSyslogLevel=`` | list | –       | Skip levels (e.g., ``debug``).                              |
+--------------------+----------+-------------+-------------------------------------------------------------+

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
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: ini

   [Network]
   Address=192.168.8.101:514
   LogFormat=rfc3339

Custom Structured Data
^^^^^^^^^^^^^^^^^^^^^

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
   ExcludeSyslogFacility=auth,authpriv
   ExcludeSyslogLevel=debug

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

Files
-----

/etc/systemd/netlogd.conf
   Main configuration.

/etc/systemd/netlogd.conf.d/*.conf
   Drop-in snippets.

/lib/systemd/system/systemd-netlogd.service
   Service unit.

Troubleshooting
---------------

- **No forwarding**: Check ``journalctl -u systemd-netlogd``; verify network and permissions.
- **TLS errors**: Use ``openssl verify -CAfile cert.pem server.crt``; set ``TLSCertificateAuthMode=allow`` for testing.
- **Test setup**: Generate logs with ``logger -p user.info "Test"``; receive with ``nc -u -l 514``.
- **Debug mode**: Override service: ``systemctl edit systemd-netlogd`` and add ``StandardOutput=journal+console``.

See Also
--------

:manpage:`systemd.socket(5)`, :manpage:`systemd.time(5)`, :manpage:`socket(7)`, :manpage:`tcp(7)`, :manpage:`systemd-journald(8)`

- RFC 5424, RFC 5425, RFC 3339, RFC 6012
- Project: https://github.com/systemd/systemd-netlogd

Author
------

Susant Sahani <ssahani@gmail.com>

Colophon
--------

This page is part of systemd-netlogd (version 1.4.4, October 27, 2025).
