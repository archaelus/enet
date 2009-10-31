%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Protocol Codec registry
%% @end
%%%-------------------------------------------------------------------
-module(enet_codec).

%% API
-export([module/1
         ,decode/2
         ,encode/2
        ]).

%%====================================================================
%% API
%%====================================================================

module(eth) -> enet_eth;
module(ethernet) -> enet_eth;
module(arp) -> enet_arp;
module(ipv4) -> enet_ipv4;
module(udp) -> enet_udp;
module(dns) -> enet_dns;
module(icmp) -> enet_icmp.

decode(Type, Data) ->
    try
        Mod = module(Type),
        case Mod:decode(Data) of
        {error, _} -> Data;
        Decoded -> Decoded
        end
    catch
        _:_ -> Data
    end.

encode(Type, Data) ->
    Mod = module(Type),
    Mod:encode(Data).

%%====================================================================
%% Internal functions
%%====================================================================
