%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet ICMP codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_icmp).

%% API
-export([decode/2
         ,encode/1
         ,encode/2
         ,expand/1
        ]).

-include("enet_types.hrl").


%%====================================================================
%% API
%%====================================================================

%% <<8,0,119,214,168,9,0,0,74,236,139,70,0,0,22,234,
%%   8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
%%   24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,
%%   39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,
%%   54,55>> -- ICMP data.

decode(Pkt = <<Type, Code, Checksum:16/big,
              ID:16/big, Sequence:16/big,
              Data/binary>>, _DecodeOpts) ->
    IcmpType = decode_type({Type, Code}),
    #icmp{type=IcmpType,
          csum=enet_checksum:oc16_check(Pkt, Checksum),
          id=ID,seq=Sequence,
          data=Data}.

expand(Pkt = #icmp{type=Type}) when is_atom(Type) ->
    expand(Pkt#icmp{type=encode_type(Type)});
expand(Pkt = #icmp{type={Type, Code}
                   ,csum=Checksum
                   ,id=ID
                   ,seq=Sequence
                   ,data=Data})
  when not is_integer(Checksum),
       is_integer(Type), is_integer(Code),
       is_integer(ID), is_integer(Sequence),
       is_binary(Data) ->
    CSumPkt = <<Type, Code, 0:16/big,
               ID:16/big, Sequence:16/big,
               Data/binary>>,
    expand(Pkt#icmp{csum=enet_checksum:oc16_sum(CSumPkt)});
expand(Pkt = #icmp{type={Type, Code}
                   ,csum=Checksum
                   ,id=ID
                   ,seq=Sequence
                   ,data=Data})
  when is_integer(Type), is_integer(Code),
       is_integer(Checksum),
       is_integer(ID), is_integer(Sequence),
       is_binary(Data) ->
    Pkt.

encode(Pkt, _PsuedoHdr) ->
    encode(expand(Pkt)).

encode(#icmp{type={Type, Code}
             ,csum=Checksum
             ,id=ID
             ,seq=Sequence
             ,data=Data}) when is_integer(Type), is_integer(Code),
                               is_integer(ID), is_integer(Sequence),
                               is_binary(Data) ->
    <<Type, Code, Checksum:16/big,
     ID:16/big, Sequence:16/big,
     Data/binary>>;
encode(Pkt) ->
    encode(expand(Pkt)).

%%====================================================================
%% Internal functions
%%====================================================================

decode_type({8, 0}) -> echo_request;
decode_type({0, 0}) -> echo_reply;
decode_type({Type, Code}) -> {Type, Code}.

encode_type(echo_request) -> {8, 0};
encode_type(echo_reply) -> {0, 0}.
