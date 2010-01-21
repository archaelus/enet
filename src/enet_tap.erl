%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Tap port program interface
%% @end
%%%-------------------------------------------------------------------
-module(enet_tap).

%% API
-export([open/0, open/1,
         if_config/2,
         test/0, listen/0,
         spawn_listen/0, listen_init/0]).

-compile(export_all).

-include("types.hrl").

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
            " -i " ++ Device
    end.

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

test() ->
    P = open(),
    lists:all(fun (N) ->
                      Test = iolist_to_binary(io_lib:format("Test packet ~p", [N])),
                      io:format("Sending test: ~p~n", [Test]),
                      port_command(P, Test),
                      {ok, Test} =:= read(P)
              end, lists:seq(1,1000)),
    close(P).

read(P) ->
    receive
        {P, {exit_status, N}} ->
            {error, {exit, N}};
        {P, {data, Data}} ->
            {ok, Data};
        E -> {error, {unexpected, E}}
    after
        timer:seconds(1) ->
            timeout
    end.

listen() ->
    listen(open()).

listen(P) ->
    receive
        {P, {exit_status, N}} ->
            erlang:exit({exit_status, N});
        {P, {data, Data}} ->
            try
                io:format("~p: Received packet: ~p~n",
                          [calendar:local_time(),
                           enet_eth:decode(Data)])
            catch
                Type:Error ->
                    io:format("~p: Couldn't decode packet ~p~nbecause ~p:~p~nStack ~p~n",
                              [calendar:local_time(), Data, Type, Error,
                               erlang:get_stacktrace()])
            end,
            listen(P);
        shutdown ->
            normal;
        E ->
            io:format("~p: Got random message ~p~n",
                      [calendar:local_time(),
                       E]),
            listen(P)
    end.

spawn_listen() ->
    proc_lib:start(?MODULE, listen_init, []).

listen_init() ->
    P = open(),
    proc_lib:init_ack({ok, self(), P}),
    listen(P).

decode(<<0>>) ->
    running;
decode(<<1, Data/binary>>) ->
    {frame, Data}.

%%====================================================================
%% Internal functions
%%====================================================================

arp() ->
    arp("8A:7E:6F:94:5D:E9", "192.168.2.2", "192.168.2.1").

arp(ESrc, SenderIP, TargetIP) ->
    #eth{src=ESrc, dst=broadcast, type=arp,
         data=#arp{htype=ethernet, ptype=ipv4,
                   sender={ESrc, SenderIP},
                   target={"00:00:00:00:00:00", TargetIP},
                   op=request } }.
