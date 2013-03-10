%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Enet Interface process
%% @end
%%%-------------------------------------------------------------------
-module(enet_eth_iface).

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

-define(DEFAULT_MAC, <<16#00,16#00,16#00,16#aa,16#bb,16#cc>>).

-record(state, {dev :: string(),
                mac = ?DEFAULT_MAC :: ethernet_address(),
                port :: port(),
                pubsub = pubsub:new() :: pubsub:pubsub(),
                osifconfig :: string(),
                promisc = false :: boolean()
               }).

%%====================================================================
%% API
%%====================================================================

start_link(Device, IfConfig) when is_list(Device), is_list(IfConfig) ->
    gen_server:start_link(?MODULE, [#state{dev=Device,
                                           mac=?DEFAULT_MAC}, IfConfig], []).

start(Device, IfConfig) when is_list(Device), is_list(IfConfig) ->
    gen_server:start(?MODULE, [#state{dev=Device}, IfConfig], []).


send({?MODULE, Pid}, Data) ->
    send(Pid, Data);
send(Pid, Data) when is_pid(Pid) ->
    gen_server:cast(Pid, {send, Data}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @private
init([S = #state{dev=Device}, IfConfig]) ->
    Port = enet_tap:open(Device),
    {ok, S#state{port=Port
                 ,osifconfig=IfConfig
                 ,pubsub=pubsub:new()}}.

%% @private
handle_call({set_promisc, Bool}, _From, S = #state{}) when is_boolean(Bool) ->
    {reply, Bool, S#state{promisc = Bool}};
handle_call({pubsub, Op}, _From, S = #state{pubsub=P}) ->
    NewPub = pubsub:process_msg(Op, P),
    {reply, ok, S#state{pubsub=NewPub}};
handle_call(Call, _From, State) ->
    ?WARN("Unexpected call ~p.", [Call]),
    {noreply, State}.

%% @private
handle_cast({send, #eth{src = Src} = Pkt}, S = #state{mac = Mac}) ->
    PktSrc = case Src of
                 undefined -> Mac;
                 _ -> Src
             end,
    Frame = enet_codec:encode(eth, Pkt#eth{src = PktSrc}, []),
    handle_cast({send, #raw{data=Frame}}, S);
handle_cast({send, #raw{data=Frame}}, S = #state{port=P})
  when is_port(P), is_binary(Frame) ->
    publish_tx(Frame, unknown, S),
    port_command(P, Frame),
    {noreply, S};
handle_cast(Msg, State) ->
    ?WARN("Unexpected cast ~p", [Msg]),
    {noreply, State}.

%% @private
handle_info({Port, {exit_status, N}}, S = #state{port=Port}) ->
    {stop, {interface_shutdown, N}, S#state{port=undefined}};
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

handle_frame(Frame, S) ->
    try enet_codec:decode(eth, Frame, [{decode_types, [eth]}]) of
        E = #eth{dst=D} when D =:= S#state.mac; D =:= broadcast ->
            %% Frames destined for me.
            publish_rx(Frame, E, S);
        E = #eth{} when S#state.promisc =:= true ->
            %% Frames destined for something else but we're in promiscuous mode.
            publish_rx(Frame, E, S);
        Frame when S#state.promisc =:= true ->
            publish_rx(Frame, unknown, S);
        _ ->
            drop_frame
    catch
        Class:Ex ->
            ?INFO("~p:~p~nStack: ~p~nFrame:~p",
                  [Class, Ex, erlang:get_stacktrace(),
                   Frame]),
            drop_frame
    end,
    {noreply, S}.

%% @private
terminate(Reason, S = #state{port=P}) when is_port(P) ->
    catch enet_tap:close(P),
    terminate(Reason, S#state{port=undefined});
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, {state, Dev, Port, Pubsub, Osifconfig}, _Extra) ->
    {state, Dev, ?DEFAULT_MAC, Port, Pubsub, Osifconfig};
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

publish_rx(Frame, Decoded, S = #state{}) ->
    publish({rx, Frame, Decoded}, S).

publish_tx(Frame, Term, S = #state{}) ->
    publish({tx, Frame, Term}, S).

publish(Message, #state{pubsub=P}) ->
    pubsub:send({enet, {?MODULE, self()}, Message}, P).
