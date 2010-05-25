{application, enet,
 [{description, "Erlang Network Interface"}
  ,{vsn, "0.1"}
  ,{applications, [kernel, stdlib]}
%  ,{mod, {enet_app, []}}
  ,{env, []}
  ,{modules, [
              enet_arp
              ,enet_checksum
              ,enet_codec
              ,enet_dns
              ,enet_eth
              ,enet_icmp
              ,enet_if_arp
              ,enet_if_crtest
              ,enet_if_dump
              ,enet_if_icmp
              ,enet_if_udp
              ,enet_if_tcp
              ,enet_iface
              ,enet_ipv4
              ,enet_pcap
              ,enet_services
              ,enet_srcgen
              ,enet_tap
              ,enet_tcp
              ,enet_udp
             ]}
  ,{registered, []}
 ]}.
