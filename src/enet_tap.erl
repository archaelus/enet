%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Tap port program interface
%% @end
%%%-------------------------------------------------------------------
-module(enet_tap).

%% API
-export([open/0
         ,open/1
         ,if_config/2
         ,close/1
         ]).

-compile(export_all).

-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

open() -> open("tap0").

open(Device) ->
    open_port({spawn, driver() ++ args(Device)},
              [{packet, 2},binary,exit_status,
               {env, env()}]).

driver() ->
    case os:type() of
        {unix, _} ->
            filename:join([priv_dir(), "bin", "enet_tap"])
    end.

args(Device) when is_list(Device) ->
    case os:type() of
        {unix, darwin} ->
            " -f /dev/" ++ Device;
        {unix, linux} ->
            " -i " ++ Device ++ " -b " ++ mtu(Device)
    end.

mtu(Device) ->
    {ok, Devopt} = inet:ifget(Device, [mtu]),
    integer_to_list(proplists:get_value(mtu, Devopt)).

env() ->
    case os:type() of
        {unix, darwin} ->
            [{"EVENT_NOKQUEUE", "1"},
             {"EVENT_NOPOLL", "1"}];
        {unix, _} ->
            []
    end.

priv_dir() ->
    {file, File} = code:is_loaded(?MODULE),
    LibDir = filename:dirname(filename:dirname(File)),
    filename:join([LibDir, "priv"]).

close(P) ->
    port_close(P).

if_config(Device, Options) when is_list(Device), is_list(Options) ->
    case os:type() of
        {unix, _} ->
            Cmd = io_lib:format("sudo /sbin/ifconfig ~s ~s", [Device, Options]),
            case os:cmd(lists:flatten(Cmd)) of
                "" -> ok;
                String ->
                    {error, String}
            end
    end.

decode(<<0>>) ->
    running;
decode(<<1, Data/binary>>) ->
    {frame, Data}.
