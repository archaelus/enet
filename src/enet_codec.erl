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
         ,packet_type/1
         ,extract/2
         ,extract/3
        ]).

%%====================================================================
%% API
%%====================================================================

module(eth) -> enet_eth;
module(ethernet) -> enet_eth;
module(arp) -> enet_arp;
module(ipv4) -> enet_ipv4;
module(ipv6) -> enet_ipv6;
module(udp) -> enet_udp;
module(dns) -> enet_dns;
module(icmp) -> enet_icmp;
module(tcp) -> enet_tcp;
module(null) -> enet_nullink.

types() ->
    [eth, ethernet, arp, ipv4, ipv6, udp, dns, icmp, tcp, null].

decode(Type, Data) ->
    decode(Type, Data, [Type]).

decode(Type, Data, [all]) ->
    decode(Type, Data, types());
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

packet_type(T) when is_tuple(T) ->
    Tag = element(1, T),
    case lists:member(Tag, types()) of
        true -> Tag;
        false -> erlang:error({badarg, Tag})
    end.

extract(TargetType, Packet) when is_tuple(Packet) ->
    extract(TargetType, packet_type(Packet), Packet).

extract(TargetType, Type, Packet) ->
    Mod = module(Type),
    case Mod:payload_type(Packet) of
        TargetType ->
            TargetPacket = Mod:payload(Packet),
            case TargetPacket of
                L when is_list(L) ->
                    find_type(TargetType, L);
                _ -> TargetPacket
            end;
        IntermediateType when IntermediateType =/= Type ->
            extract(TargetType, IntermediateType, Mod:payload(Packet))
    end.

find_type(TargetType, []) -> erlang:error({missing, TargetType});
find_type(TargetType, [Packet | Rest]) when is_tuple(Packet) ->
    case packet_type(Packet) of
        TargetType -> Packet;
        _ -> find_type(TargetType, Rest)
    end.

%%====================================================================
%% Internal functions
%%====================================================================
