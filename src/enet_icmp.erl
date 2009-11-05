%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet ICMP codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_icmp).

%% API
-export([decode/1
         ,decode/2
         ,encode/1
        ]).

-include("types.hrl").


%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @spec () ->
%% @doc 
%% @end 


decode(Data) -> decode(Data, []).

%% <<8,0,119,214,168,9,0,0,74,236,139,70,0,0,22,234,
%%   8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,
%%   24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,
%%   39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,
%%   54,55>> -- ICMP data.

decode(<<Type, Code, Checksum:16/big,
        ID:16/big, Sequence:16/big,
        Data/binary>>, _DecodeOpts) ->
    IcmpType = decode_type({Type, Code}),
    #icmp{type=IcmpType,csum=Checksum,id=ID,seq=Sequence,
          data=Data}.

encode(foo) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

decode_type({8, 0}) -> echo_request;
decode_type({0, 0}) -> echo_reply;
decode_type({Type, Code}) -> {Type, Code}.

encode_type(echo_request) -> {8, 0};
encode_type(echo_reply) -> {0, 0};
encode_type({Type, Code}) -> {Type, Code}.
