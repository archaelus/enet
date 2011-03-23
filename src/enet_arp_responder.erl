%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ARP address cache and translator
%% @end
%%%-------------------------------------------------------------------
-module(enet_arp_responder).

-behaviour(gen_server).

-include("logging.hrl").
-include("enet_types.hrl").
-include_lib("eunit/include/eunit.hrl").

%% API
-export([start_link/0]).
-export([attach/2
         ,eth_addr/2
         ,ip_addr/2
         ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {tid}).

%% Table entries
-define(ARP_ENTRY(Mac, Addr), {Addr, Mac}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @spec start_link() -> {ok,Pid} | ignore | {error,Error}
%% @doc Starts the server
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link(?MODULE, [], []).

attach(Interface) ->
    {ok, Pid} = start_link(),
    attach(Pid, Interface).

attach(Dumper, Interface) ->
    gen_server:call(Dumper, {sub, Interface}),
    {ok, Dumper}.

eth_addr(Cache, IpAddr) ->
    gen_server:call(Cache, {eth_addr, IpAddr}).

ip_addr(Cache, EthAddr) ->
    gen_server:call(Cache, {ip_addr, EthAddr}).


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
init([]) ->
    Tid = ets:new(?MODULE, []),
    {ok, #state{tid=Tid}}.

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

handle_call({sub, Interface}, _From, State) ->
    {reply, pubsub:sync_subscribe(Interface), State};

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

%% handle_info({enet, _IF, {tx, Frame}}, State) ->
%%     P = enet_codec:decode(eth, Frame, [all]),
%%     print([{dir, send}, {raw, Frame}, {packet, P}], State),
%%     {noreply, State};
%% handle_info({enet, _IF, {RX, Frame}}, State)
%%   when RX =:= rx;
%%        RX =:= promisc_rx ->
%%     print([{dir, recv}, {raw, Frame}], State),
%%     {noreply, State};
handle_info({enet, IF, {RX, Frame, Pkt = #eth{type=arp}}}, State)
  when RX =:= rx;
       RX =:= promisc_rx ->
    handle_arp_rx(IF, Pkt, State),
    {noreply, State};

handle_info(Info, State) ->
    ?WARN("Unexpected info ~p", [Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @spec terminate(Reason, State) -> void()
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%% @end
%%--------------------------------------------------------------------
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

handle_arp_rx(IF, #eth{type=arp,data=Pkt}, State) ->
    try enet_codec:decode(arp, Pkt) of
        {error, bad_packet} ->
            %% XXX - log corrupt arp packet somehow?
            ignore;
        #arp{} = Q ->
            handle_arp_rx(IF, Q, State)
    catch
        _Type:_Error ->
            %% XXX - couldn't decode Pkt, Type:Error.
            ignore
    end;

handle_arp_rx(IF,
              Q = #arp{htype = ethernet,
                       ptype = Type,
                       op = request,
                       sender = Sender = {SMac, SAddr},
                       target = {TMac, TAddr}
                      },
              State) ->
    case cache_lookup(TAddr, State) of
        [] ->
            ignore;
        [?ARP_ENTRY(CMac, CAddr)] ->
            R = #arp{op = reply,
                     htype = ethernet,
                     ptype = Type,
                     sender = {CMac, CAddr},
                     target = Sender
                    },
            Reply = #eth{dst=SMac, type=arp, data=enet_codec:encode(arp, R)},
            enet_host:send(Reply)
    end.


cache_lookup(Key, #state{tid=T}) ->
    ets:lookup(T, Key).
