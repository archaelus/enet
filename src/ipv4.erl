%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc IPv4 Codec
%% @end
%%%-------------------------------------------------------------------
-module(ipv4).

%% API
-export([encode_addr/1, decode_addr/1,
         addr_len/0]).

%%====================================================================
%% API
%%====================================================================

addr_len() -> 4.

decode_addr(B) when is_binary(B) ->
    string:join([ erlang:integer_to_list(N) || <<N:8>> <= B], ".").

encode_addr(A) when is_binary(A), byte_size(A) =:= 6 -> A;
encode_addr(L) when is_list(L) ->
    << << (erlang:list_to_integer(Oct)):8 >>
       || Oct <- string:tokens(L, ".") >>.

%%====================================================================
%% Internal functions
%%====================================================================
