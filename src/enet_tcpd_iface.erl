%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Enet Interface process
%% @end
%%%-------------------------------------------------------------------
-module(enet_tcpd_iface).

-behaviour(gen_server).

-include_lib("logging.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("enet_types.hrl").
-include("enet_pcap.hrl").

-define(TAP, enet_tap_tcpd).

%% API
-export([start_link/1
         ,start/1
         ,start_link/2
         ,start/2
         ,send/2
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {port :: port(),
                pubsub = pubsub:new() :: pubsub:pubsub(),
                args :: list(),
                header :: #pcap_hdr{},
                buf  :: 'undefined' | {BytesNeeded::non_neg_integer(), binary()}
               }).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @spec start_link(Device, OSIfconfig) -> {ok,Pid} | ignore | {error,Error}
%% @doc Starts the server
%% @end
%%--------------------------------------------------------------------
start_link(Args) when is_list(Args) ->
    gen_server:start_link(?MODULE, [#state{args=Args}], []).

start_link(Args, Pubsub) when is_list(Args) ->
    gen_server:start_link(?MODULE, [#state{args=Args, pubsub=Pubsub}], []).


start(Args) when is_list(Args) ->
    gen_server:start(?MODULE, [#state{args=Args}], []).

start(Args, Pubsub) when is_list(Args) ->
    gen_server:start(?MODULE, [#state{args=Args, pubsub=Pubsub}], []).


send(_Interface, _Data) ->
    erlang:error(not_supported).

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
init([S = #state{args=Args}]) ->
    Port = ?TAP:open(Args),
    {ok, S#state{port=Port}}.

%%--------------------------------------------------------------------
%% @private
handle_call({pubsub, Op}, _From, S = #state{pubsub=P}) ->
    NewPub = pubsub:process_msg(Op, P),
    {reply, ok, S#state{pubsub=NewPub}};
handle_call(Call, _From, State) ->
    ?WARN("Unexpected call ~p.", [Call]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
handle_cast(Msg, State) ->
    ?WARN("Unexpected cast ~p", [Msg]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
handle_info({Port, {exit_status, 0}}, S = #state{port=Port}) ->
    {stop, normal, S#state{port=undefined}};
handle_info({Port, {exit_status, N}}, S = #state{port=Port}) ->
    {stop, {tcpdump_error, N}, S#state{port=undefined}};

handle_info({Port, {data, Data}}, S = #state{port=Port,
                                             buf=undefined}) ->
    S1 = handle_port_data(Data, S),
    {noreply, S1};
handle_info({Port, {data, Data}}, S = #state{port=Port,
                                             buf={N, Buf}}) ->
    case byte_size(Data) of
        Sz when Sz >= N ->
            {noreply,
             handle_port_data(<<Buf/binary, Data/binary>>,
                              S#state{buf=undefined})};
        Sz when Sz < N ->
            {noreply,
             S#state{buf={N-Sz, <<Buf/binary, Data/binary>>}}}
    end;

handle_info({pubsub, Op}, S = #state{pubsub=P}) ->
    {noreply, S#state{pubsub=pubsub:process_msg(Op, P)}};
handle_info(PubSubOp = {'DOWN', _, _, _, _}, S = #state{pubsub=P}) ->
    {noreply, S#state{pubsub=pubsub:process_msg(PubSubOp, P)}};
handle_info(Info, State) ->
    ?WARN("Unexpected info ~p", [Info]),
    {noreply, State}.

%% handle_frame(Frame, S) ->
%%     case enet_codec:decode(eth, Frame, [eth]) of
%%         E = #eth{dst=D} when D =:= S#state.mac; D =:= broadcast ->
%%             %% Frames destined for me.
%%             publish_rx(Frame, E, S);
%%         E = #eth{} when S#state.promisc =:= true ->
%%             %% Frames destined for something else but we're in promiscuous mode.
%%             publish_rx(Frame, E, S);
%%         Frame when S#state.promisc =:= true ->
%%             publish_rx(Frame, unknown, S);
%%         _ ->
%%             drop_frame
%%     end,
%%     {noreply, S}.

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
    catch ?TAP:close(P),
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

publish_rx(Frame, Decoded, S = #state{}) ->
    publish({rx, Frame, Decoded}, S).

publish_tx(Frame, Term, S = #state{}) ->
    publish({tx, Frame, Term}, S).

publish(Message, #state{pubsub=P}) ->
    pubsub:send({enet, {?MODULE, self()}, Message}, P).

handle_port_data(Header, S = #state{header=undefined})
  when byte_size(Header) < 24 ->
    S#state{buf={24 - byte_size(Header), Header}};
handle_port_data(Header, S = #state{header=undefined})
  when byte_size(Header) >= 24 ->
    case enet_pcap:decode_header(Header) of
        {PcapHdr = #pcap_hdr{}, Rest} ->
            handle_port_data(Rest, S#state{header=PcapHdr})
    end;
handle_port_data(Data, S = #state{header=Hdr}) ->
    case enet_pcap:partial_decode(Data, Hdr) of
        {Pkt, Rest} ->
            handle_packet(Pkt, S),
            handle_port_data(Rest, S);
        N when is_integer(N) ->
            S#state{buf={N, Data}}
    end.

handle_packet(Pcap = #pcap_pkt{},
              S = #state{header=Hdr}) ->
    publish(Pcap, S),
    S.
