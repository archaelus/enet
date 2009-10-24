%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Ethernet frame codec 
%% @end
%%%-------------------------------------------------------------------
-module(eth).

%% API
-export([decode/1, decode/2, encode/1,
         decode_type/1, encode_type/1,
         decode_addr/1, encode_addr/1,
         addr_len/0]).

-include("types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(Packet) ->
    decode(Packet, decode_data).

decode(<<Dest:6/binary,
        Src:6/binary,
        Type:16/big,
        Data/binary>>, decode_data) ->
    PType = decode_type(Type),
    #eth{src=decode_addr(Src),dst=decode_addr(Dest),
         type=PType,data=(codec:module(PType)):decode(Data)};
decode(<<Dest:6/binary,
        Src:6/binary,
        Type:16/big,
        Data/binary>>, _) ->
    PType = decode_type(Type),
    #eth{src=decode_addr(Src),dst=decode_addr(Dest),
         type=PType,data=Data}.

encode(P = #eth{src=Src}) when is_list(Src) ->
    encode(P#eth{src=encode_addr(Src)});
encode(P = #eth{dst=Dest}) when is_list(Dest) ->
    encode(P#eth{dst=encode_addr(Dest)});
encode(P = #eth{type=Type, data=Data}) when is_atom(Type), is_tuple(Data) ->
    encode(P#eth{data=(codec:module(Type)):encode(Data)});

encode(#eth{src=Src,dst=Dest,type=Type,data=Data})
  when is_binary(Src), is_binary(Dest), is_atom(Type), is_binary(Data) ->
    <<Src:6/binary,
     Dest:6/binary,
     (encode_type(Type)):16/big,
     Data/binary>>.
% IOList form.
%    [ Src, Dest, << encode_type(Type):16/big>>, Data ].

%%====================================================================
%% Internal functions
%%====================================================================

decode_type(16#0800) -> ipv4;
decode_type(16#0806) -> arp;
decode_type(16#0835) -> rarp;
decode_type(16#86DD) -> ipv6.

encode_type(ipv4) -> 16#0800;
encode_type(arp) -> 16#0806;
encode_type(rarp) -> 16#0835;
encode_type(ipv6) -> 16#86DD.

decode_addr(B) when is_binary(B) ->
    string:join([ erlang:integer_to_list(N, 16) || <<N:8>> <= B], ":").

encode_addr(A) when is_binary(A), byte_size(A) =:= 6 -> A;
encode_addr(L) when is_list(L) ->
    << << (erlang:list_to_integer(Oct, 16)):8 >>
       || Oct <- string:tokens(L, ":") >>.

addr_len() -> 6.
