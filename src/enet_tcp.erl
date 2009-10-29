%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc TCP codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_tcp).

%% API
-export([decode_port/1, encode_port/1]).

%%====================================================================
%% API
%%====================================================================

decode_port(Port) ->
    enet_services:decode_port(tcp, Port).

encode_port(Port) ->
    enet_services:encode_port(tcp, Port).

%%====================================================================
%% Internal functions
%%====================================================================
