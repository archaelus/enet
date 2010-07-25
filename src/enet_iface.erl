%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Enet Interface process
%% @end
%%%-------------------------------------------------------------------
-module(enet_iface).

-behaviour(gen_server).

-include_lib("logging.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("enet_types.hrl").

%% API
-export([start_link/2
         ,start/2
         ,send/2
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {dev, port, pubsub, osifconfig}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @spec start_link(Device, OSIfconfig) -> {ok,Pid} | ignore | {error,Error}
%% @doc Starts the server
%% @end
%%--------------------------------------------------------------------
start_link(Device, IfConfig) when is_list(Device), is_list(IfConfig) ->
    gen_server:start_link(?MODULE, [#state{dev=Device}, IfConfig], []).

start(Device, IfConfig) when is_list(Device), is_list(IfConfig) ->
    gen_server:start(?MODULE, [#state{dev=Device}, IfConfig], []).

send(Interface, Data) ->
    gen_server:cast(Interface, {send, Data}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%%--------------------------------------------------------------------
%% @private
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore               |
%%                     {stop, Reason}
%% @doc Initialises the server's state
%% @end
%%--------------------------------------------------------------------
init([S = #state{dev=Device}, IfConfig]) ->
    Port = enet_tap:open(Device),
    {ok, S#state{port=Port
                 ,osifconfig=IfConfig
                 ,pubsub=pubsub:publish()}}.

%%--------------------------------------------------------------------
%% @private
%% @spec 
%% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% @doc Call message handler callbacks
%% @end
%%--------------------------------------------------------------------
handle_call({pubsub, Op}, _From, S = #state{pubsub=P}) ->
    NewPub = pubsub:process_msg(Op, P),
    {reply, ok, S#state{pubsub=NewPub}};
handle_call(Call, _From, State) ->
    ?WARN("Unexpected call ~p.", [Call]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @spec 
%% handle_cast(Msg, State) -> {noreply, State} |
%%                            {noreply, State, Timeout} |
%%                            {stop, Reason, State}
%% @doc Cast message handler callbacks
%% @end
%%--------------------------------------------------------------------
handle_cast({send, Data}, S = #state{port=P}) when is_port(P) ->
    case Data of
        Frame when is_binary(Frame) ->
            port_command(P, Frame);
        BadPacket ->
            ?WARN("Couldn't send bad packet: ~p", [BadPacket])
    end,
    {noreply, S};
handle_cast(Msg, State) ->
    ?WARN("Unexpected cast ~p", [Msg]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @spec 
%% handle_info(Info, State) -> {noreply, State} |
%%                             {noreply, State, Timeout} |
%%                             {stop, Reason, State}
%% @doc Non gen-server message handler callbacks
%% @end
%%--------------------------------------------------------------------
handle_info({Port, {exit_status, N}}, S = #state{port=Port}) ->
    {stop, {interface_shutdown, N}, S = #state{port=undefined}};
handle_info({Port, {data, PortPacket}}, S = #state{port=Port}) ->
    case enet_tap:decode(PortPacket) of
        running ->
            #state{dev=Device, osifconfig=IfConfig} = S,
            ?INFO("~p came up, configuring OS: ~s", [Device, IfConfig]),
            ok = enet_tap:if_config(Device, IfConfig),
            {noreply, S};
        {frame, Frame} ->
            handle_frame(Frame, S)
    end;
handle_info({pubsub, Op}, S = #state{pubsub=P}) ->
    {noreply, S#state{pubsub=pubsub:process_msg(Op, P)}};
handle_info(PubSubOp = {'DOWN', _, _, _, _}, S = #state{pubsub=P}) ->
    {noreply, S#state{pubsub=pubsub:process_msg(PubSubOp, P)}};
handle_info(Info, State) ->
    ?WARN("Unexpected info ~p", [Info]),
    {noreply, State}.

handle_frame(Frame, S = #state{pubsub=P}) ->
    pubsub:send({enet, {?MODULE, self()}, {rx, Frame}}, P),
    {noreply, S}.

%%--------------------------------------------------------------------
%% @private
%% @spec terminate(Reason, State) -> void()
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%% @end
%%--------------------------------------------------------------------
terminate(Reason, S = #state{port=P}) when is_port(P) ->
    enet_tap:close(P),
    terminate(Reason, S#state{port=undefined});
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @doc Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
