%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Codec tester (try to re-encode packets and report errors)
%% @end
%%%-------------------------------------------------------------------
-module(enet_if_crtest).

-behaviour(gen_event).
%% API
-export([attach/2
        ]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("enet_types.hrl").

-record(state, {dir}).

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
attach(Interface, DumpDir) ->
    gen_event:add_handler(enet_iface:event_manager(Interface),
                          ?MODULE, [DumpDir]).

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
init([DumpDir]) ->
    {ok, #state{dir=DumpDir}}.

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
handle_event({out, _Frame, _P}, State) ->
    {ok, State};
handle_event({in, Frame, P = #eth{}}, S = #state{dir=Dir}) ->
    try
        enet_codec:encode(eth, P)
    catch
        error:undef ->
            [{Mod,Fn,Args} | Stack] = erlang:get_stacktrace(),
            error_logger:warning_msg("Unimplmented encoding function ~p:~p/~p.",
                                     [Mod, Fn, length(Args)]),
            dump(error, undef, Mod, Fn, Args, Stack, Frame, Dir);
        Type:Exception ->
            {_,_,Mics} = erlang:now(),
            {_,{H, M, Secs}} = calendar:local_time(),
            Micros = Mics div 1000,
            Seconds = Secs rem 60 + (Micros / 1000),
            [{Mod,Fn,Args} | Stack] = erlang:get_stacktrace(),
            error_logger:warning_msg("~p:~p:~p Re-encoding error -- ~p:~p~nPacket: ~p~nCall: ~s~nStack: ~p",
                                     [H, M, Seconds, Type, Exception, P,
                                      fmt_call(Mod, Fn, Args),
                                      Stack]),
            dump(Type, Exception, Mod, Fn, Args, Stack, Frame, Dir)
    end,
    {ok, S};
handle_event(Event, State) ->
    error_logger:warning_msg("Unexpected event ~p", [Event]),
    {ok, State}.

dump(Type, Exception, M, F, A, Stack, Frame, Dir) ->
    FileName = io_lib:format("~p:~p_~p-~p:~p", [M, F, length(A), Type, Exception]),
    FullName = filename:join(Dir, FileName ++ ".dmp"),
    file:write_file(FullName,
                    iolist_to_binary(io_lib:format("%% ~p:~p -- ~w~n"
                                                   "~s.~n",
                                                   [Type, Exception, Stack,
                                                    fmt_call(M, F, A)]))),
    enet_pcap:append_to_file(Frame, filename:join(Dir, FileName ++ ".pcap")).

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
handle_call(Msg , State) ->
    error_logger:warning_msg("Unexpected call ~p", [Msg]),
    {ok, ok, State}.

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

fmt_call(M, F, A) when is_atom(M), is_atom(F), is_list(A) ->
    PrintedArgs = [ io_lib:format("~p", [Arg]) || Arg <- A],
    io_lib:format("~p:~p(~s)", [M, F, string:join(PrintedArgs, ",")]).
