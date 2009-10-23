%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc 
%% @end
%%%-------------------------------------------------------------------
-module(tap).

%% API
-export([open/0, test/0, listen/0,
         spawn_listen/0, listen_init/0]).

-compile(export_all).

-include("types.hrl").

%%====================================================================
%% API
%%====================================================================

open() ->
    P = open_port({spawn, "sudo -E ./c_src/mactap"},
                  [{packet, 2},binary,exit_status,
                   {env, [{"EVENT_NOKQUEUE", "1"},
                          {"EVENT_NOPOLL", "1"}]}]),
    P.

close(P) ->
    port_close(P).

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
                           eth:decode(Data)])
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

%%====================================================================
%% Internal functions
%%====================================================================

send_arp(P) ->
    send_arp(P, "8a:7e:6f:94:5d:e9", "192.168.2.2", "192.168.2.1").

send_arp(P, ESrc, SenderIP, TargetIP) ->
    Pkt = eth:encode(#eth{src=ESrc, dst="ff:ff:ff:ff:ff:ff", type=arp,
                    data=#arp{htype=ethernet, ptype=ipv4,
                              sender={ESrc, SenderIP},
                              target={"0:0:0:0:0:0", TargetIP},
                              op=request } }),
    port_command(P, Pkt).
