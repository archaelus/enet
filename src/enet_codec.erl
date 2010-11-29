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
         ,decode/3
         ,encode/2
         ,encode/3
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
module(icmp) -> enet_icmp;
module(tcp) -> enet_tcp.

decode(Type, Data) ->
    decode(Type, Data, [Type]).

decode(Type, Data, [all]) ->
    decode(Type, Data, [eth, ethernet, arp, ipv4, udp, dns, icmp, tcp]);
decode(Type, Data, Options) ->
    case lists:member(Type, Options) of
        true ->
            try
                Mod = module(Type),
                case Mod:decode(Data, Options) of
                    {error, _} -> Data;
                    Decoded -> Decoded
                end
            catch
                C:E ->
                    error_logger:error_msg("~p ~p:~p ~p",
                                           [self(), C, E,
                                            erlang:get_stacktrace()]),
                    Data
            end;
        false -> Data
    end.

encode(Type, Data) ->
    Mod = module(Type),
    Mod:encode(Data).

encode(Type, Data, OuterPacket) ->
    Mod = module(Type),
    Mod:encode(Data, OuterPacket).

%%====================================================================
%% Internal functions
%%====================================================================
