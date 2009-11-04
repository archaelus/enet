%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc 
%% @end
%%%-------------------------------------------------------------------
-module(enet_if_arp).

-behaviour(gen_event).
%% API
-export([attach/1
         ,add_entry/3
        ]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("types.hrl").

-record(state, {iface,
                table=orddict:new()}).

-record(arp_entry,
        {eth :: ethernet_address,
         ip :: ip_address,
         type :: 'static' | {'dynamic', time}
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

add_entry(Interface, EthAddress, IPAddress) ->
    gen_event:call(enet_iface:event_manager(Interface),
                   ?MODULE,
                   {add_entry,
                    #arp_entry{eth=EthAddress,
                               ip=IPAddress,
                               type=static}}).
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
    {ok, #state{iface=Interface}}.

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
handle_event({in, _Frame,
              #eth{src=SrcEth,dst=broadcast,type=arp,
                   data=#arp{htype=ethernet,ptype=ipv4,
                             op=request,
                             sender={SrcEth,SrcIP},
                             target={_,TargetIP}}}},
             State = #state{iface=IF, table=T}) ->
    case orddict:find(TargetIP, T) of
        {ok, #arp_entry{eth=TargetEth, type=static}} ->
            R = arp_reply({SrcEth,SrcIP}, {TargetEth, TargetIP}),
            enet_iface:send(IF, R),
            {ok, State};
        {ok, #arp_entry{eth=_TargetEth, type=_}} ->
            %% Not a static entry, don't answer requests
            {ok, State};
        error ->
            %% No entry
            {ok, State}
    end;
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
handle_call({add_entry, E = #arp_entry{ip=IP}}, State = #state{table=T}) ->
    {ok, ok, State#state{table=orddict:store(IP, E, T)}};
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

arp_reply(Sender = {SEth, _SIP}, Target = {TEth, _TIP}) ->
    #eth{src=TEth, dst=SEth, type=arp,
         data=#arp{op=reply,htype=ethernet,ptype=ipv4,
                   sender=Target,
                   target=Sender}}.
