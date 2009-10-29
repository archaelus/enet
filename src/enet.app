{application, enet,
 [{description, "Erlang Network Interface"}
  ,{vsn, "0.1"}
  ,{applications, [kernel, stdlib]}
%  ,{mod, {enet_app, []}}
  ,{env, []}
  ,{modules, [
              enet_arp
              ,enet_codec
              ,enet_dns
              ,enet_eth
              ,enet_ipv4
              ,enet_services
              ,enet_srcgen
              ,enet_tap
              ,enet_tcp
              ,enet_udp
             ]}
  ,{registered, []}
 ]}.
