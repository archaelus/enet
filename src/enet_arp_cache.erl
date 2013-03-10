%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ARP cache datastructure
%% @end
-module(enet_arp_cache).

-include("enet_arp_cache.hrl").

-opaque cache() :: [#entry{}].

-export_type([cache/0]).

-export([new/0
         ,lookup_ip_addr/2
         ,lookup_eth_addr/2
         ,publish/3
         ]).

-spec new() -> cache().
new() ->
    [].

lookup_eth_addr(EthAddr, Cache) ->
    case lists:keyfind(EthAddr, #entry.ethaddr, Cache) of
        #entry{} = E -> E;
        false -> not_found
    end.

lookup_ip_addr(IpAddr, Cache) ->
    case lists:keyfind(IpAddr, #entry.ipaddr, Cache) of
        #entry{} = E -> E;
        false -> not_found
    end.

publish(EthAddr, IpAddr, Cache) ->
    [#entry{ethaddr = EthAddr,
            ipaddr = IpAddr,
            publish = true}
     | Cache].
