==================================================
ENet - A pure-Erlang network stack
==================================================

ENet is a pure Erlang network stack that can be used to encode and
decode a variety of common packet formats.

The project includes a port program that can be used to send and
receive ethernet frames via the ``/dev/tap0`` device.

Requirements
============

Mac OS X
  ``libevent``, OS X 10.6.1 (probably compatible with other versions), the
  ``tuntaposx`` driver ( http://tuntaposx.sourceforge.net ) loaded, ``sudo``.

Linux
  libevent, the ``tun`` module loaded, the ``tunctl`` program (usually
  in the ``uml-utilities`` package``), ``sudo``.

Drivers
=======

Mac OS X
  The ``enet_tap`` port program. Takes a mandatory option ``-f`` to
  specify which tap device to use. (normally "/dev/tap0")

Linux
  The ``enet_tap`` port program. Takes a mandatory ``-i`` argument
  that specifies which tap device to use. (normally "tap0")


Building the Driver
===================

You'll need to edit the ``Makefile`` to set the appropriate ``CFLAGS``
and ``LDFLAGS`` for your machine and ``erts`` (32 or 64 bit build,
location of libevent headers and libraries, ...).


Setting up the tap device
=========================

Mac OS X
--------

For ease of use, you should probably change the ownership of ``/dev/tapN``
to yourself.

Linux
-----

You should create a tap device that you can open as your user. The
easiest way to do this is to install the ``tunctl`` program (in the
``uml-utilities`` package on debian systems), and then create the
device::

    tunctl -u yourusername -t tap0

Setup sudo
==========

Enet currently uses the ``ifconfig`` command to configure the
operating system side of the tap device. This is usually a privileged
operation, so we need to configure sudo to allow erlang to do this
without a password.

Add the following lines to ``/etc/sudoers``::
    
    Cmnd_Alias	ENET = /sbin/ifconfig tap0 *
    yourusername ALL=(ALL) NOPASSWD: ENET

Starting Enet
=============

From an erlang shell (``erl -boot start_sasl -pa ebin``)::

    1> {ok, Arp} = enet_arp_responder:start(),
       enet_arp_responder:publish(Arp, enet_eth_iface:default_mac(),
                                  <<192,168,2,2>>),
       {ok, Eth} = enet_eth_iface:start("tap0", "192.168.2.1/24 up"),
       {ok, Dumper} = enet_if_dump:attach(Eth),
       enet_arp_responder:attach(Arp, Eth).

You should now see decoded traffic in the erlang shell. If you ping
the IP address of the erlang interface ``192.168.2.2`` in the example,
you should see ping replies and an arp entry (``arp -na``)::

    ? (192.168.2.2) at 0:0:0:aa:bb:cc on tap0 ifscope [ethernet]
