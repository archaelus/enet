%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Protocol Codec registry
%% @end
%%%-------------------------------------------------------------------
-module(enet_codec).
-compile(native).

%% API
-export([module/1
         ,decode/3
         ,encode/3
         ,encode/4
         ,packet_type/1
         ,extract/3
         ,extract/4
         ,payload/2
         ,payload/3
         ,payload_type/2
         ,payload_type/3
         ,decompose/4
        ]).

-export([behaviour_info/1]).

%%====================================================================
%% Behaviour
%%====================================================================

behaviour_info(callbacks) ->
    [{decode, 2}
     ,{payload, 2}
     ,{payload_type, 2}
     ,{encode, 2}
     ,{default_options, 0}
    ];
behaviour_info(_) -> undefined.

%%====================================================================
%% API
%%====================================================================

module(eth) -> enet_eth;
module(ethernet) -> module(eth);
module(arp) -> enet_arp;
module(ipv4) -> enet_ipv4;
module(ipv6) -> enet_ipv6;
module(udp) -> enet_udp;
module(dns) -> enet_dns;
module(icmp) -> enet_icmp;
module(tcp) -> enet_tcp;
module(null) -> enet_nullink;
module(pcap) -> enet_pcap;
module(pcap_pkt) -> module(pcap);
module(_) -> {error, unknown_packet_type}.

decode(Type, Data, Options) ->
    TypesToDecode = proplists:get_value(decode_types, Options, [Type]),
    case TypesToDecode =:= all orelse lists:member(Type, TypesToDecode) of
        true ->
            {Mod, MOpts} = mod_options(Type, Options),
            NewOpts = update_decode_types(MOpts,
                                          {decode_types, TypesToDecode}),
            true = Mod =/= error,
            case Mod:decode(Data, NewOpts) of
                {error, _} -> Data;
                Decoded -> Decoded
            end;
        false -> Data
    end.

encode(Type, Data, Options) ->
    {Mod, MOpts} = mod_options(Type, Options),
    Mod:encode(Data, MOpts).

encode(Type, Data, OuterPacket, Options) ->
    {Mod, MOpts} = mod_options(Type, Options),
    Mod:encode(Data, OuterPacket, MOpts).

packet_type(T) when is_tuple(T) ->
    element(1, T).

extract(TargetType, Packet, Options) when is_tuple(Packet) ->
    extract(TargetType, packet_type(Packet), Packet, Options).

extract(TargetType, Type, Packet, Options) when is_tuple(Packet) ->
    {Mod, MOpts} = mod_options(Type, Options),
    case Mod:payload_type(Packet, MOpts) of
        TargetType ->
            TargetPacket = Mod:payload(Packet, MOpts),
            case TargetPacket of
                L when is_list(L) ->
                    find_type(TargetType, L, Options);
                _ -> TargetPacket
            end;
        IntermediateType when IntermediateType =/= Type ->
            extract(TargetType, IntermediateType,
                    Mod:payload(Packet, MOpts), Options)
    end.

find_type(TargetType, [], _) -> erlang:error({missing, TargetType});
find_type(TargetType, [Packet | Rest], Options) when is_tuple(Packet) ->
    case packet_type(Packet) of
        TargetType -> Packet;
        _ -> find_type(TargetType, Rest, Options)
    end.

payload_type(Pkt, Options) ->
    PktType = packet_type(Pkt),
    payload_type(PktType, Pkt, Options).

payload_type(PktType, Pkt, Options) ->
    {Mod, MOpts} = mod_options(PktType, Options),
    Mod:payload_type(Pkt, MOpts).

payload(Pkt, Options) ->
    PktType = packet_type(Pkt),
    payload(PktType, Pkt, Options).

payload(PktType, Pkt, Options) ->
    {Mod, MOpts} = mod_options(PktType, Options),
    Mod:payload(Pkt, MOpts).

decompose(Types, PktType, Pkt, Options) ->
    decompose(Types, PktType, Pkt, Options, []).

decompose(Types, PktType, Pkt, Options, Layers) when is_binary(Pkt)->
    case mod_options(PktType, Options) of
        {error, unknown_packet_type} -> Layers;
        {Mod, MOpts} ->
            Packet = Mod:decode(Pkt, MOpts),
            decompose(Types, PktType, Packet, Options, Layers)
    end;
decompose(Types, PktType, Packet, Options, Layers) when is_tuple(Packet) ->
    Acc = [Packet | Layers],
    case mod_options(PktType, Options) of
        {error, unknown_packet_type} ->
            Acc;
        {Mod, Opts} ->
            try Mod:payload_type(Packet, Opts) of
                PayloadType ->
                    case lists:member(PayloadType, Types) of
                        true ->
                            Payload = Mod:payload(Packet, Opts),
                            decompose(Types, PayloadType, Payload,
                                      Options, Acc);
                        false -> Acc
                    end
            catch error:undef -> Acc
            end
    end.

%%====================================================================
%% Internal functions
%%====================================================================

mod_options(Type, Options) ->
    case module(Type) of
        {error, _} = E -> E;
        Mod when is_atom(Mod) ->
            Defaults = try Mod:default_options()
                       catch _:_ -> Options end,
            {Mod, proplists:get_value(Mod, Options, Defaults)}
    end.

update_decode_types(OptList, {decode_types, L})
  when is_list(OptList) ->
    proplists:delete(decode_types, OptList),
    OptList ++ [{decode_types, L}].
