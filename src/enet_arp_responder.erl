%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ARP address cache and translator
%% @end
%%%-------------------------------------------------------------------
-module(enet_arp_responder).

-behaviour(gen_server).

-include("../include/logging.hrl").
-include("../include/enet_types.hrl").
-include("enet_arp_cache.hrl").
-include_lib("eunit/include/eunit.hrl").

%% API
-export([start/0]).
-export([attach/1
         ,attach/2
         ,eth_addr/2
         ,ip_addr/2
         ,arp_filter/1
         ,publish/3
         ,get_cache/1
         ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(state, {cache}).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @spec start_link() -> {ok,Pid} | ignore | {error,Error}
%% @doc Starts the server
%% @end
%%--------------------------------------------------------------------
start() ->
    gen_server:start(?MODULE, [], []).

attach(Interface) ->
    {ok, Pid} = start(),
    attach(Pid, Interface).

attach(Dumper, Interface) ->
    gen_server:call(Dumper, {sub, Interface}),
    {ok, Dumper}.

eth_addr(Pid, IpAddr) ->
    gen_server:call(Pid, {eth_addr, IpAddr}).

ip_addr(Pid, EthAddr) ->
    gen_server:call(Pid, {ip_addr, EthAddr}).

publish(Pid, EthAddr, IpAddr) ->
    gen_server:call(Pid, {publish, EthAddr, IpAddr}).

get_cache(Pid) ->
    gen_server:call(Pid, get_cache).

arp_filter({enet, _, {rx, _, #eth{type=arp}}}) -> true;
arp_filter(_) -> false.

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @private
init([]) ->
    {ok, #state{cache = enet_arp_cache:new()}}.

%% @private
handle_call(get_cache, _From, State = #state{cache = Cache}) ->
    {reply, Cache, State};
handle_call({publish, EthAddr, IpAddr}, _From,
            State = #state{cache = OldCache}) ->
    NewCache = enet_arp_cache:publish(EthAddr, IpAddr, OldCache),
    {reply, ok, State#state{cache = NewCache}};
handle_call({eth_addr, IpAddr}, _From, State = #state{cache = Cache}) ->
    case enet_arp_cache:lookup_ip_addr(IpAddr, Cache) of
        not_found ->
            {reply, not_found, State};
        #entry{ethaddr = Addr} ->
            {reply, Addr, State}
    end;

handle_call({ip_addr, EthAddr}, _From, State = #state{cache = Cache}) ->
    case enet_arp_cache:lookup_eth_addr(EthAddr, Cache) of
        not_found ->
            {reply, not_found, State};
        #entry{ipaddr = Addr} ->
            {reply, Addr, State}
    end;

handle_call({sub, Interface}, _From, State) ->
    {reply, pubsub:sync_subscribe(Interface, fun ?MODULE:arp_filter/1), State};

handle_call(Call, _From, State) ->
    ?WARN("Unexpected call ~p.", [Call]),
    {noreply, State}.

%% @private
handle_cast(Msg, State) ->
    ?WARN("Unexpected cast ~p", [Msg]),
    {noreply, State}.

handle_info({enet, IF, {RX, _Frame, Pkt = #eth{type=arp}}}, State)
  when RX =:= rx;
       RX =:= promisc_rx ->
    NewState = handle_arp_rx(IF, Pkt, State),
    {noreply, NewState};


handle_info(Info, State) ->
    ?WARN("Unexpected info ~p", [Info]),
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

handle_arp_rx(IF, #eth{type=arp,data=Pkt}, State) ->
    try enet_codec:decode(arp, Pkt, [{decode_types, [arp]}]) of
        #arp{htype = ethernet,
             ptype = ipv4,
             op=request} = Q ->
            handle_arp_request(IF, Q, State);
        _ ->
            ?INFO("Ignoring arp:~n~p", [Pkt]),
            State
    catch
        Class:Error ->
            ?WARN("~p:~p while decoding~n~p~nStack:~p",
                  [Class, Error, Pkt, erlang:get_stacktrace()]),
            %% XXX - couldn't decode Pkt, Type:Error.
            State
    end.

handle_arp_request({enet_eth_iface, IF},
                   #arp{htype = ethernet,
                        ptype = ipv4,
                        op = request,
                        sender = Sender = {SMac, SAddr},
                        target = {_TMac, TAddr}},
                   State = #state{cache = Cache}) ->
    case enet_arp_cache:lookup_ip_addr(TAddr, Cache) of
        #entry{publish = true,
               ethaddr = CMac,
               ipaddr = TAddr} ->
            R = #arp{op = reply,
                     htype = ethernet,
                     ptype = ipv4,
                     sender = {CMac, TAddr},
                     target = Sender
                    },
            Reply = #eth{dst=SMac, type=arp,
                         data=enet_codec:encode(arp, R, [])},
            enet_eth_iface:send(IF, Reply),
            State#state{cache = Cache};
        _ when SAddr =:= TAddr ->
            %% They're advertising themselves, so learn anyway. YOLO.
            NewCache = enet_arp_cache:learn(SMac, SAddr, Cache),
            State#state{cache = NewCache};
        _ ->
            State
    end.
