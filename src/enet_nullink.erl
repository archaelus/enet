%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Enet null interface codec
%% @end
-module(enet_nullink).

%% API
-behavior(enet_codec).
-export([decode/2
         ,payload/2
         ,payload_type/2
         ,encode/2
         ,default_options/0
        ]).


-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(Frame, Options) ->
    {OS,End} = {proplists:get_value(os, Options, darwin),
                proplists:get_value(endianness, Options, little)},
    decode(Frame,OS, End, Options).

decode(<<Type:32/little, Data/binary>>, OS = darwin, little, Options) ->
    LinkType = decode_type(OS, Type),
    #null{type=LinkType, data=enet_codec:decode(LinkType, Data, Options)}.


encode(#null{type=LinkType, data=Data}, Options) when is_binary(Data) ->
    {OS,End} = {proplists:get_value(os, Options, darwin),
                proplists:get_value(endianness, Options, little)},
    encode(encode_type(OS, LinkType), Data, OS, End).

encode(LinkType, Data, darwin, little) when is_integer(LinkType),
                                            is_binary(Data) ->
    << LinkType:32/little, Data/binary>>.


payload_type(#null{type=T}, _) -> T.
payload(#null{data=D}, _) -> D.

default_options() -> [].

%%====================================================================
%% Internal functions
%%====================================================================

decode_type(darwin, 2) -> ipv4;
decode_type(darwin, 30) -> ipv6;
decode_type(darwin, N) -> N.

encode_type(darwin, ipv4) -> 2;
encode_type(darwin, ipv6) -> 30;
encode_type(darwin, N) -> N.
