%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet Interface UDP responder
%% @end
%%%-------------------------------------------------------------------
-module(enet_if_udp).

-behaviour(gen_event).
%% API
-export([attach/1
         ,add_listener/4
        ]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("types.hrl").
-include("logging.hrl").


-define(DICT, orddict).

-record(state, {iface,
                table=?DICT:new()}).

-record(udp_sock,
        {ip :: ipv4_address()
         ,port :: port_no()
         ,proc :: fun ((#udp{}) -> any())
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
                    #udp_sock{ip=IPAddress,
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

%% {eth,"6E:93:B4:10:27:64",broadcast,ipv4,
%%  {ipv4,4,5,0,78,57863,[],0,64,udp,correct,"192.168.2.1",
%%   "192.168.2.255",[],
%%   {udp,49569,<<"netbios-ns">>,58,correct,
%%    <<67,68,1,16,0,1,0,0,0,0,0,0,32,70,72,69,
%%      80,70,67,69,76,69,72,70,67,69,80,70,70,
%%      70,65,67,65,67,65,67,65,67,65,67,65,67,
%%      65,66,78,0,0,32,0,1>>}}}
%% #eth{src = "6E:93:B4:10:27:64",dst = broadcast,type = ipv4,
%%      data = #ipv4{vsn = 4,hlen = 5,diffserv = 0,totlen = 78,
%%                   id = 57863,flags = [],frag_offset = 0,ttl = 64,proto = udp,
%%                   hdr_csum = correct,src = "192.168.2.1",
%%                   dst = "192.168.2.255",options = [],
%%                   data = #udp{src_port = 49569,dst_port = <<"netbios-ns">>,
%%                               length = 58,csum = correct,
%%                               data = <<67,68,1,16,0,1,0,0,0,0,0,0,32,70,72,69,80,70,
%%                                        67,69,76,69,72,70,67,69,80,70,70,70,65,67,65,
%%                                        67,65,67,65,67,65,67,65,67,65,66,78,0,0,32,0,1>>}}}
handle_event({in, _Frame,
              #eth{type=ipv4,
                   data=#ipv4{dst=IP,
                              proto=udp,
                              data=Pkt}}},
             State = #state{iface=_IF, table=T}) ->
    #udp{dst_port=Port} = Pkt,
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
handle_call({listen, S = #udp_sock{port=Port}},
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
                [#udp_sock{ip=IP, proc=Proc} | _Rest]) ->
    Proc(Pkt);
deliver_sockets(Pkt, _IP,
                [#udp_sock{ip='_', proc=Proc} | _Rest]) ->
    Proc(Pkt);
deliver_sockets(Pkt, IP, [_Sock | Rest]) ->
    deliver_sockets(Pkt, IP, Rest).
