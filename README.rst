==================================================
ENet - A pure-Erlang network stack
==================================================

ENet is a pure Erlang network stack that can be used to encode and
decode a variety of common packet formats.

The project includes a port program that can be used to send and
receive ethernet frames via the /dev/tap0 device.

Drivers
=======

mactap
  The ``mactap`` port program requires libevent, Mac OS X (tested
  on OS X 10.6.1) and the tuntaposx driver
  (http://tuntaposx.sourceforge.net). All options are currently hard
  coded.


Use
===

(Ensure your user can sudo and you have run a sudo command recently so
you won't be prompted for a password)


    (in an erlang shell:)
    1> {ok, Pid, Port} = enet_tap:spawn_listen().
    {ok,<0.33.0>,#Port<0.581>}

(Now configure the interface as root in another shell:
# ifconfig tap0 192.168.2.1 netmask 255.255.255.0 broadcast 192.168.2.255 up
)

(You should now see decoded traffic in the erlang shell.)
