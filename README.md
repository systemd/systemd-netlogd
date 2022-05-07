systemd-netlogd
===================

[![Build Status](https://travis-ci.org/systemd/systemd-netlogd.svg?branch=master)](https://travis-ci.org/systemd/systemd-netlogd)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/systemd/systemd-netlogd.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/systemd/systemd-netlogd/alerts/)

Forwards messages from the journal to other hosts over the network using
the Syslog Protocol (RFC 5424). It can be configured to send messages to
both unicast and multicast addresses. systemd-netlogd runs with own user
systemd-journal-netlog.  Starts sending logs when network is up and stops
sending as soon as network is down (uses sd-network). It reads from journal
and forwards to network one by one. It does not use any extra disk space.

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
    sudo useradd -r -d / -s /usr/sbin/nologin -g systemd-journal systemd-journal-netlog


Configuration
-------------

systemd-networkd reads configuration files named `/etc/systemd/systemd-netlogd.conf` and `/etc/systemd/systemd-netlogd.conf.d/*.conf`.

**[NETWORK]** SECTION OPTIONS


       The "[Network]" section only applies for UDP multicast address and Port:

       Address=
           Controls whether log messages received by the systemd daemon shall be forwarded
           to a unicast UDP address or multicast UDP network group in syslog RFC 5424 format.

           The the address string format is similar to socket units. See systemd.socket(1)
           
       Protocol=
            Specifies whether to use udp or tcp protocol. Defaults to udp.

       Optional settings

       StructuredData=
           Meta information about the syslog message, which can be used for Cloud Based
           syslog servers, such as Loggly

**EXAMPLE**

 Example 1. /etc/systemd/systemd-netlogd.conf

    [Network]
    Address=239.0.0.1:6000
    #Protocol=udp
Example 2. /etc/systemd/systemd-netlogd.conf

    [Network]
    Address=192.168.8.101:514
    #Protocol=udp

Example 3. /etc/systemd/systemd-netlogd.conf

    [Network]
    Address=192.168.8.101:514
    #Protocol=udp
    StructuredData=[1ab456b6-90bb-6578-abcd-5b734584aaaa@41058]
