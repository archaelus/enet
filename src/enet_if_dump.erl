%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc TCPDUMP like traffic printer.
%% @end
%%%-------------------------------------------------------------------
-module(enet_if_dump).

-behaviour(gen_server).
%% API
-export([start_link/0
         ,attach/1
         ,attach/2
         ,change_format/2
         ,hexblock/1
        ]).

%% gen_event callbacks
-export([init/1, handle_cast/2, handle_call/3, 
         handle_info/2, terminate/2, code_change/3]).

-include("enet_types.hrl").
-include_lib("logging.hrl").

-record(state, {print=[time, space, direction, space, packet, nl
                       ,{hexblock, frame}, nl
                       ,frame]}).

start_link() ->
    gen_server:start_link(?MODULE, [], []).

attach(Interface) ->
    {ok, Pid} = start_link(),
    attach(Pid, Interface).

attach(Dumper, Interface) ->
    gen_server:call(Dumper, {sub, Interface}),
    {ok, Dumper}.

change_format(Dumper, Format) ->
    gen_server:call(Dumper,
                   {change_format, Format}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({sub, Interface}, _From, State) ->
    {reply, pubsub:sync_subscribe(Interface), State};
handle_call({change_format, Format}, _From, State) ->
    {reply, ok, State#state{print=Format}}.

handle_cast(Msg, State) ->
    ?WARN("Unexpected cast, ~p", [Msg]),
    {noreply, State}.

handle_info({enet, _IF, {tx, Frame}}, State) ->
    P = enet_codec:decode(eth, Frame, [all]),
    print([{dir, send}, {raw, Frame}, {packet, P}], State),
    {noreply, State};
handle_info({enet, _IF, {RX, Frame}}, State)
  when RX =:= rx;
       RX =:= promisc_rx ->
    print([{dir, recv}, {raw, Frame}], State),
    {noreply, State};
handle_info({enet, _IF, {RX, Frame, Pkt}}, State)
  when RX =:= rx;
       RX =:= promisc_rx ->
    print([{dir, recv},
           {raw, Frame},
           {packet, enet_codec:decode(eth, Frame, [all])}],
          State),
    {noreply, State};
handle_info(Msg, State) ->
    print([time, space, {fmt, "msg: ~p", Msg}], State),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

print(Info, #state{print=Format}) ->
    {Fmt, Args} = lists:foldl(fun (FmtArg, Acc) -> format(FmtArg, Info, Acc) end,
                              {"", []},
                              Format),
    error_logger:info_msg(Fmt, Args).

format(time, _Info, {Fmt, Args}) ->
    {_,_,Mics} = erlang:now(),
    {_,{H, M, Secs}} = calendar:local_time(),
    Micros = Mics div 1000,
    Seconds = Secs rem 60 + (Micros / 1000),
    {Fmt ++ "~p:~p:~p", Args ++ [H, M, Seconds]};
format(space, _Info, {Fmt, Args}) ->
    {Fmt ++ " ", Args};
format(nl, _Info, {Fmt, Args}) ->
    {Fmt ++ "~n", Args};
format({fmt, F, A}, _Info, {Fmt, Args}) ->
    {Fmt ++ F, Args ++ A};
format(direction, Info, {Fmt, Args}) ->
    Dir = proplists:get_value(dir, Info),
    {Fmt ++ "~p", Args ++ [Dir]};
format(packet, Info, {Fmt, Args}) ->
    P = proplists:get_value(packet, Info),
    {Fmt ++ "~p", Args ++ [P]};
format(frame, Info, {Fmt, Args}) ->
    F = proplists:get_value(raw, Info),
    {Fmt ++ "frame ~p", Args ++ [F]};
format({hexblock, frame}, Info, {Fmt, Args}) ->
    F = proplists:get_value(raw, Info),
    {Fmt ++ "Frame:~n~s", Args ++ [hexblock(F)]}.

hexblock(Bin) ->
    FullLineBytes = (byte_size(Bin) div 16) * 16,
    <<FullLines:FullLineBytes/binary, LastLine/binary>> = Bin,
    Lines = [Line || <<Line:16/binary>> <= Bin ],
    NumberedLines = lists:zip(lists:seq(0, FullLineBytes-1, 16), Lines),
    [ [hexblock_line(Offset, Line) || {Offset, Line} <- NumberedLines],
     hexblock_lastline(FullLineBytes, LastLine)].

hexblock_line(Offset, Line) ->
    %"0x0000:  4500 0045 0000 0000 4001 f564 c0a8 0202  E..E....@..d...."
    Groups = [ io_lib:format("~4.16.0b", [Group]) || << Group:16 >> <= Line ],
    JGroups = string:join(Groups, " "),
    io_lib:format("0x~4.16.0b:  ~s~n", [Offset, JGroups]).

hexblock_lastline(Offset, Line) ->
    Size = byte_size(Line),
    FullGroupSize = (Size div 2) * 2,
    LastGroupSize = (Size - FullGroupSize) * 8,
    <<FullGroup:FullGroupSize/binary, LastGroup:LastGroupSize>> = Line,
    Groups = [ io_lib:format("~4.16.0b", [Group]) || << Group:16 >> <= FullGroup ],
    JGroups = string:join(Groups, " "),
    case LastGroupSize of
        0 ->
            io_lib:format("0x~4.16.0b:  ~s~n", [Offset, JGroups]);
        _ ->
            io_lib:format("0x~4.16.0b:  ~s~n",
                          [Offset, [JGroups, " ",
                                    erlang:integer_to_list(LastGroup, 16)]])
    end.
