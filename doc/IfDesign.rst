Enet Interface Stack Redesign
=============================

Layers
------

* enet_if_phy ?

  Would open the tap port and read raw frames to hand off to
  ethernet. Much like enet_tap right now.

* enet_if_ethernet

  * enet_if_arp ?

    Best if this happens at the eth layer as we need to do arp queries
    when trying to send packets from the ip layer.

* enet_if_ipv4

  * enet_if_icmp

* enet_if_tcp, enet_if_udp

One goal of the redesign is to avoid the complete decode on receive
approach we're using in v1. In v1, the enet_iface process completely
decodes each packet as it is received. This is unnecessary in the case
that the packet has an incorrect checksum at the lower layers, in the
case that the packet is not addressed to us anyway, or we're not
expecting the packet for some other reason.

Decoding the packet layer by layer allows us to stop early if we need to.

Concurrency
-----------

What is the unit of concurrency for a network stack? Two obvious
candidates - network stack layers (ethernet, ipv4, tcp, tcp sockets,
and so on) and individual packets.

A process-per-packet design would tax the spawn rate of the VM, and
means that information shared in a layer would need to be exchanged by
ets table or something.

A process-per-layer design gives bounded concurrency, we're not going
to spawn-bomb the VM, but limits the concurrency we can achieve. We
may end up serializing all the packets through one ipv4 process for
example.


Nevertheless, it's tempting to try the process-per-layer design first.

PubSub
------

Currently enet uses gen_event stacks as a publish-subscribe mechanism
to distribute packets between layers. This is a very basic mechanism,
it doesn't allow any send-side filtering. We're also using it in a
very basic manner - the entire stack in a single gen_event process -
which means each part of the stack sees all packets.

Dynamic assembly of networks of processes with send-side filtering
would be very handy to have, so how do we do this in Plain Old Erlang?

A first design which doesn't filter is::

    loop(Subscribers) ->
        receive
            {sub, Pid} ->
                erlang:monitor(process, Pid),
                loop([Pid | Subscribers]);
            {unsub, Pid} ->
                loop(lists:delete(Pid, Subscribers));
            {'DOWN', _, _, Pid, _} ->
                loop(lists:delete(Pid, Subscribers));
            Packet ->
                [ Pid ! {enet_pkt, self(), Packet}
                  || Pid <- Subscribers ]
                loop(Subscribers)
        end.

The protocol being::

    {sub, SubscriberPid}
    {unsub, SubscriberPid}
    {enet_pkt, SourcePid, Packet}
