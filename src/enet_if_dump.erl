%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc TCPDUMP like traffic printer.
%% @end
%%%-------------------------------------------------------------------
-module(enet_if_dump).

-behaviour(gen_event).
%% API
-export([attach/1
         ,change_format/2
         ,hexblock/1
        ]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("types.hrl").

-record(state, {print=[time, space, direction, space, packet, nl, {hexblock, frame}]}).

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Adds an event handler
%%
%% @spec attach() -> ok | {'EXIT', Reason} | term()
%% @end
%%--------------------------------------------------------------------
attach(Interface) ->
    gen_event:add_handler(enet_iface:event_manager(Interface),
                          ?MODULE, []).

change_format(Interface, Format) ->
    gen_event:call(enet_iface:event_manager(Interface),
                   ?MODULE, {change_format, Format}).

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a new event handler is added to an event manager,
%% this function is called to initialize the event handler.
%%
%% @spec init(Args) -> {ok, State}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    {ok, #state{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever an event manager receives an event sent using
%% gen_event:notify/2 or gen_event:sync_notify/2, this function is
%% called for each installed event handler to handle the event.
%%
%% @spec handle_event(Event, State) ->
%%                          {ok, State} |
%%                          {swap_handler, Args1, State1, Mod2, Args2} |
%%                          remove_handler
%% @end
%%--------------------------------------------------------------------
handle_event({out, Frame, P = #eth{}}, State) ->
    print([{dir, send}, {raw, Frame}, {packet, P}], State),
    {ok, State};
handle_event({in, Frame, P = #eth{}}, State) ->
    print([{dir, recv}, {raw, Frame}, {packet, P}], State),
    {ok, State};
handle_event(Event, State) ->
    print([time, space, {fmt, "event: ~p", Event}], State),
    {ok, State}.

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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever an event manager receives a request sent using
%% gen_event:call/3,4, this function is called for the specified
%% event handler to handle the request.
%%
%% @spec handle_call(Request, State) ->
%%                   {ok, Reply, State} |
%%                   {swap_handler, Reply, Args1, State1, Mod2, Args2} |
%%                   {remove_handler, Reply}
%% @end
%%--------------------------------------------------------------------
handle_call({change_format, Format}, State) ->
    {ok, ok, State#state{print=Format}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for each installed event handler when
%% an event manager receives any other message than an event or a
%% synchronous request (or a system message).
%%
%% @spec handle_info(Info, State) ->
%%                         {ok, State} |
%%                         {swap_handler, Args1, State1, Mod2, Args2} |
%%                         remove_handler
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever an event handler is deleted from an event manager, this
%% function is called. It should be the opposite of Module:init/1 and
%% do any necessary cleaning up.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
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
