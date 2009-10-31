==================================================
ENet - A pure-Erlang network stack
==================================================

ENet is a pure Erlang network stack that can be used to encode and
decode a variety of common packet formats.

The project includes a port program that can be used to send and
receive ethernet frames via the /dev/tap0 device.

Drivers
=======

``enet_tap``
  The ``enet_tap`` port program requires libevent, Mac OS X (tested
  on OS X 10.6.1) and the tuntaposx driver
  (http://tuntaposx.sourceforge.net). All options are currently hard
  coded.


Use
===

For ease of use, you should probably change the ownership of ``/dev/tapN``
to yourself, and allow passwordless sudo to the command
``/sbin/ifconfig tapN``. You can do this in /etc/sudoers by::
    
    Cmnd_Alias	ENET = /sbin/ifconfig tap0 *
    yourusername ALL=(ALL) NOPASSWD: ENET

From an erlang shell (with -boot start_sasl)::

    1> {ok, If} = enet_iface:start("tap0", "192.168.2.1/24 up"),
       enet_if_dump:attach(If).

You should now see decoded traffic in the erlang shell.
