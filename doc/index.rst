:orphan:

systend-netlogd manual page
===========================

Description
-----------

Forwards messages from the journal to other hosts over the network using the Syslog Protocol (RFC 5424 and RFC 3339). It can be configured to send
messages to both unicast and multicast addresses. systemd-netlogd runs with own user systemd-journal-netlog. Starts sending logs when network is up and stops
sending as soon as network is down (uses sd-network). It reads from journal and forwards to network one by one. It does not use any extra disk space.
systemd-netlogd supports ``UDP``, ``TCP``, ``TLS`` and ``DTLS`` (Datagram Transport Layer Security RFC 6012).

Configuration
-------------

|
| **useradd** -G systemd-journal systemd-journal-netlog

This will create a user systemd-journal-netlog

[NETWORK] SECTION OPTIONS
-------------------------
|
|
   The "[Network]" section only applies for UDP multicast address and Port:

| ``Address=``
        Controls whether log messages received by the systemd daemon shall be forwarded
        to a unicast UDP address or multicast UDP network group in syslog RFC 5424 format.
        The address string format is similar to socket units. See systemd.socket(1)

| ``Protocol=``
        Specifies whether to use udp, tcp, tls or dtls (Datagram Transport Layer Security) protocol. Defaults to udp.

| ``LogFormat=``
        Specifies whether to use RFC 5424, RFC 5425, or RFC 3339 format. Takes one of rfc5424, rfc5425, or rfc3339. Defaults to rfc5424. RFC 5425 is mainly useful for sending over TLS; it prepends a message length field to the RFC 5424 format.

| ``Directory=``
        Takes a directory path. Specifies whether to operate on the specified journal directory DIR instead of the default runtime and system journal paths.

| ``Namespace=``
        Takes a journal namespace identifier string as argument. If not specified the data collected by the default namespace is shown.
        If specified shows the log data of the specified namespace instead. If the namespace is specified as "*" data from all namespaces
        is shown, interleaved. If the namespace identifier is prefixed with "+" data from the specified namespace and the default namespace is shown,
        interleaved, but no other.

| ``ConnectionRetrySec=``
        Specifies the minimum delay before subsequent attempts to contact a Log server are made.
        Takes a time span value. The default unit is seconds, but other units may be specified,
        see systemd.time(5). Defaults to 30 seconds and must not be smaller than 1 second.

| ``TLSCertificateAuthMode=``
        Specifies whether to validate the certificate. Takes one of no, allow, deny, warn. Defaults to 'no' which disables certificate validation.

| ``KeepAlive=``
        Takes a boolean argument. If true, the TCP/IP stack will send a keep alive message after 2h (depending on the configuration of
        /proc/sys/net/ipv4/tcp_keepalive_time) for all TCP streams accepted on this socket. This controls the SO_KEEPALIVE socket option
        (see socket(7) and the TCP Keepalive HOWTO for details.) Defaults to false.

| ``KeepAliveTimeSec=``
        Takes time (in seconds) as argument. The connection needs to remain idle before TCP starts sending keepalive probes.
        This controls the TCP_KEEPIDLE socket option (see socket(7) and the TCP Keepalive HOWTO for details.) Default value is 7200 seconds (2 hours).

| ``KeepAliveIntervalSec=``
        Takes time (in seconds) as argument between individual keepalive probes, if the socket option SO_KEEPALIVE has been set on this socket.
        This controls the TCP_KEEPINTVL socket option (see socket(7) and the TCP Keepalive HOWTO for details.) Default value is 75 seconds.

| ``KeepAliveProbes=``
       Takes an integer as argument. It is the number of unacknowledged probes to send before considering the connection dead and notifying
       the application layer. This controls the TCP_KEEPCNT socket option (see socket(7) and the TCP Keepalive HOWTO for details.) Default value is 9.

| ``SendBuffer=``
       Takes an integer argument controlling the receive or send buffer sizes of this socket, respectively. This controls the SO_SNDBUF
       socket options (see socket(7) for details.). The usual suffixes K, M, G are supported and are understood to the base of 1024.

| ``NoDelay=``
       Takes a boolean argument. TCP Nagle's algorithm works by combining a number of small outgoing messages, and sending them all at once.
       This controls the TCP_NODELAY socket option (see tcp(7)). Defaults to false.

|  Optional settings

|  ``StructuredData=``
        Specifies the meta information about the syslog message, which can be used for Cloud Based syslog servers, such as Loggly.

|  ``UseSysLogStructuredData=``
        A boolean. Specifies whether to extract SYSLOG_STRUCTURED_DATA= from journal. Defaults to false.

|  ``UseSysLogMsgId=``
       A boolean. Specifies whether to extract SYSLOG_MSGID= from journal. Defaults to false.

EXAMPLES
--------

- Example 1. UDP Multicast::

 .. code-block:: bash

    [Network]
    Address=239.0.0.1:6000

- Example 2. UDP::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514

- Example 3. Structured Data::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514
    StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]

- Example 4. TLS::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514
    Protocol=tls

- Example 5. DTLS::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:4433
    Protocol=dtls

- Example 6. Custom Structured Data and Message Id::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514
    #Protocol=udp
    LogFormat=rfc5424
    UseSysLogStructuredData=yes
    UseSysLogMsgId=yes

- Example 7. TCP::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514
    Protocol=tcp

- Example 8. TLS with certificate authentication mode::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514
    Protocol=tls
    TLSCertificateAuthMode=warn

- Example 9. DTLS with certificate authentication mode::

 .. code-block:: bash

    [Network]
    Address=192.168.8.101:514
    Protocol=tls
    TLSCertificateAuthMode=deny


- Use case of UseSysLogStructuredData= and UseSysLogMsgId=::

 .. code-block:: bash

    sd_journal_send(
    "MESSAGE=%s", "Message to process",
    "PRIORITY=%s", "4",
    "SYSLOG_FACILITY=%s", "1",
    "SYSLOG_MSGID=%s", "1011",
    "SYSLOG_STRUCTURED_DATA=%s", R"([exampleSDID@32473 iut="3" eventSource="Application"])",
    NULL
  );
