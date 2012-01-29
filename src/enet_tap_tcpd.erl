%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Tap port program interface
%% @end
%%%-------------------------------------------------------------------
-module(enet_tap_tcpd).

%% API
-export([open/0
         ,open/1
         ,open/2
         ,close/1
         ]).

-compile(export_all).

-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

open() -> open("en0", "").
open(Args) ->
    open_tcpdump(Args).

open(Device, Filter) ->
    open_tcpdump(args(Device, Filter)).

open_tcpdump(Args) ->
    open_port({spawn_executable, driver()},
              [{args, Args}
               ,stream
               ,binary
               ,exit_status
               ,in
               ,use_stdio
               ,{env, env()}]).

driver() ->
    case os:type() of
        {unix, _} ->
            os:find_executable("tcpdump")
    end.

args(Device, Filter) ->
    [ "-w", "-", "-i", Device | Filter ].

env() ->
    case os:type() of
        {unix, _} ->
            []
    end.

close(P) ->
    port_close(P).
