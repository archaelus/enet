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
  (http://tuntaposx.sourceforge.net). Takes a mandatory option ``-f``
  to specify which tap device to use. (normally "/dev/tap0")


Use
===

For ease of use, you should probably change the ownership of ``/dev/tapN``
to yourself, and allow passwordless sudo to the command
``/sbin/ifconfig tapN``. You can do this in /etc/sudoers by::
    
    Cmnd_Alias	ENET = /sbin/ifconfig tap0 *
    yourusername ALL=(ALL) NOPASSWD: ENET

From an erlang shell (with -boot start_sasl)::

    1> {ok, Pid} = enet_iface:start("tap0", "192.168.2.1/24 up"),
       enet_if_dump:attach(Pid),
       enet_if_arp:attach(Pid),
       enet_if_arp:add_entry(Pid, "4A:6E:01:1B:19:8F", "192.168.2.2"),
       enet_if_icmp:attach(Pid).

You should now see decoded traffic in the erlang shell. If you ping
the IP address of the erlang interface ``192.168.2.2`` in the example,
you should see ping replies and an arp entry (``arp -na``)::

    ? (192.168.2.2) at 4a:6e:1:1b:19:8f on tap0 ifscope [ethernet]
