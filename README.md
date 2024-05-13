systemd-netlogd
===================

![build](https://github.com/systemd/systemd-netlogd/actions/workflows/ci.yml/badge.svg)

Forwards messages from the journal to other hosts over the network using
the Syslog Protocol (RFC 5424 and RFC 3339). It can be configured to send messages to
both unicast and multicast addresses. systemd-netlogd runs with own user
systemd-journal-netlog.  Starts sending logs when network is up and stops
sending as soon as network is down (uses sd-network). It reads from journal
and forwards to network one by one. It does not use any extra disk space.
systemd-netlogd supports UDP, TCP, TLS and DTLS (Datagram Transport Layer Security RFC 6012).

--------------------------------------------------------------------------


Installing from source
----------------------

Install build dependencies:

    # On Debian/Ubuntu
    sudo apt install build-essential gperf libcap-dev libsystemd-dev pkg-config meson python3-sphinx
    # On CentOS/RHEL/Fedora
    sudo dnf group install 'Development Tools'
    sudo dnf install gperf libcap-devel pkg-config systemd-devel meson python3-sphinx

Build and install:

    make
    sudo make install

Creating user:

``` bash
sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog
```
or via sysusers

``` /usr/lib/sysusers.d/systemd-netlogd.conf```
```bash
#Type   Name                    ID                      GECOS   Home directory  Shell
u       systemd-journal-netlog  -:systemd-journal       -       /               /bin/nologin
```

Configuration
-------------

systemd-netlogd reads configuration files named `/etc/systemd/netlogd.conf` and `/etc/systemd/netlogd.conf.d/*.conf`.

**[NETWORK]** SECTION OPTIONS


       The "[Network]" section only applies for UDP multicast address and Port:

       Address=
           Controls whether log messages received by the systemd daemon shall be forwarded
           to a unicast UDP address or multicast UDP network group in syslog RFC 5424 format.

           The the address string format is similar to socket units. See systemd.socket(1)

       Protocol=
            Specifies whether to use udp, tcp, tls or dtls (Datagram Transport Layer Security)  protocol. Defaults to udp.

       LogFormat=
              Specifies whether to use RFC 5424 format or RFC 3339 format. Takes one of rfc5424 or rfc3339. Defaults to rfc5424.

       Directory=
              Takes a directory path. Specifies whether to operate on the specified journal directory DIR instead of the default runtime and system journal paths.

       Namespace=
              Takes a journal namespace identifier string as argument. If not specified the data collected by the default namespace is shown. If specified
              shows the log data of the specified namespace instead. If the namespace is specified as "*" data from all namespaces is shown, interleaved.
              If the namespace identifier is prefixed with "+" data from the specified namespace and the default namespace is shown, interleaved, but no other

       ConnectionRetrySec=
               Specifies the minimum delay before subsequent attempts to contact a Log server are made.
               Takes a time span value. The default unit is seconds, but other units may be specified,
               see systemd.time(5). Defaults to 30 seconds and must not be smaller than 1 second.

       TLSCertificateAuthMode=
               Specifies whether to validate the certificate. Takes one of no, allow, deny, warn. Defaults to 'no' which disables certificate validation.

   Optional settings

       StructuredData=
           Meta information about the syslog message, which can be used for Cloud Based
           syslog servers, such as Loggly

       UseSysLogStructuredData=
          A boolean. Specifies whether to extract SYSLOG_STRUCTURED_DATA= from journal. Defaults to false.

       UseSysLogMsgId=
          A boolean. Specifies whether to extract SYSLOG_MSGID= from journal. Defaults to false.


**EXAMPLE**

 Example 1. /etc/systemd/netlogd.conf

``` sh
    [Network]
    Address=239.0.0.1:6000
    #Protocol=udp
    #LogFormat=rfc5424

```

Example 2. /etc/systemd/netlogd.conf

``` sh
    [Network]
    Address=192.168.8.101:514
    #Protocol=udp
    LogFormat=rfc3339

```

Example 3. /etc/systemd/netlogd.conf

``` sh

    [Network]
    Address=192.168.8.101:514
    #Protocol=udp
    LogFormat=rfc5424
    StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]

```

Example 4. /etc/systemd/netlogd.conf

``` sh

    [Network]
    Address=192.168.8.101:514
    #Protocol=udp
    LogFormat=rfc5424
    UseSysLogStructuredData=yes
    UseSysLogMsgId=yes

```

Use case of ```UseSysLogStructuredData=``` and ```UseSysLogMsgId=```

```
  sd_journal_send(
    "MESSAGE=%s", "Message to process",
    "PRIORITY=%s", "4",
    "SYSLOG_FACILITY=%s", "1",
    "SYSLOG_MSGID=%s", "1011",
    "SYSLOG_STRUCTURED_DATA=%s", R"([exampleSDID@32473 iut="3" eventSource="Application"])",
    NULL
  );
```
