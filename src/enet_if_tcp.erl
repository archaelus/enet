%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet Interface TCP responder
%% @end
%%%-------------------------------------------------------------------
-module(enet_if_tcp).

-behaviour(gen_event).
%% API
-export([attach/1
         ,add_listener/4
        ]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("enet_types.hrl").
-include("logging.hrl").


-define(DICT, orddict).

-record(state, {iface,
                table=?DICT:new()}).

-record(tcp_sock,
        {ip :: ipv4_address()
         ,port :: port_no()
         ,proc :: fun ((#tcp{}) -> any())
        }).

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
                          ?MODULE, [Interface]).

add_listener(Interface, IPAddress, Port, Proc) ->
    gen_event:call(enet_iface:event_manager(Interface),
                   ?MODULE,
                   {listen,
                    #tcp_sock{ip=IPAddress,
                              port=Port,
                              proc=Proc}}).

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
init([Interface]) ->
    {ok, #state{iface=Interface,
                table=?DICT:new()}}.

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

%% {eth,"FE:E6:FB:B6:D9:F3","4A:6E:01:1B:19:8F",ipv4,
%%  {ipv4,4,5,16,64,1850,
%%   [dont_fragment],
%%   0,64,tcp,correct,"192.168.2.1","192.168.2.2",[],
%%   {tcp,59990,<<"http">>,2959603421,0,11,0,false,false,false,
%%    false,true,false,65535,correct,0,
%%    [{mss,1460},
%%     {window_size_shift,3},
%%     {timestamp,705097495,0},
%%     sack_ok],
%%    <<>>}}}
handle_event({in, _Frame,
              #eth{type=ipv4,
                   data=#ipv4{dst=IP,
                              proto=tcp,
                              data=Pkt}}},
             State = #state{iface=_IF, table=T}) ->
    #tcp{dst_port=Port} = Pkt,
    deliver(Pkt, {IP, Port}, T),
    {ok, State};
handle_event(_Event, State) ->
    {ok, State}.

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
handle_call({listen, S = #tcp_sock{port=Port}},
            State = #state{table=T}) ->
    NewTable = orddict:append(Port, S, T),
    {ok,
     {ok, orddict:fetch(Port, NewTable)},
     State#state{table=NewTable}};
handle_call(_Request, State) ->
    Reply = ok,
    {ok, Reply, State}.

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

deliver(Pkt, {IP, Port}, T) ->
    case ?DICT:find(Port, T) of
        error ->
            {drop_packet, no_socket};
        {ok, Sockets} ->
            deliver_sockets(Pkt, IP, Sockets)
    end.

deliver_sockets(_Pkt, _IP, []) ->
    {drop_packet, no_matching_socket};
deliver_sockets(Pkt, IP,
                [#tcp_sock{ip=IP, proc=Proc} | _Rest]) ->
    Proc(Pkt);
deliver_sockets(Pkt, _IP,
                [#tcp_sock{ip='_', proc=Proc} | _Rest]) ->
    Proc(Pkt);
deliver_sockets(Pkt, IP, [_Sock | Rest]) ->
    deliver_sockets(Pkt, IP, Rest).
