:orphan:

systend-netlogd manual page
===========================

Description
-----------

Forwards messages from the journal to other hosts over the network using the Syslog
Protocol (RFC 5424). It can be configured to send messages to both unicast and multicast
addresses. systemd-netlogd runs with own user systemd-journal-netlog. Starts sending logs
when network is up and stops sending as soon as network is down (uses sd-network).

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

|   Address=
       Controls whether log messages received by the systemd daemon shall be forwarded
       to a unicast UDP address or multicast UDP network group in syslog RFC 5424 format.

       The the address string format is similar to socket units. See systemd.socket(1)

|  Optional settings

|  StructuredData=
       Meta information about the syslog message, which can be used for Cloud Based
       syslog servers, such as Loggly
|
|

EXAMPLES
--------

- Example 1. /etc/systemd/systemd-netlogd.conf::

       [Network]
       Address=239.0.0.1:6000
       Example 2. /etc/systemd/systemd-netlogd.conf

- Example 2. /etc/systemd/systemd-netlogd.conf::

       [Network]
       Address=192.168.8.101:514

- Example 3. /etc/systemd/systemd-netlogd.conf::

       [Network]
       Address=192.168.8.101:514
       StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]
