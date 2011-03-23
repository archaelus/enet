%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Network Host
%% @end
%%%-------------------------------------------------------------------
-module(enet_host).

-behaviour(gen_server).

-include_lib("logging.hrl").
-include_lib("eunit/include/eunit.hrl").

%% API
-export([start_link/1, start/1]).
-export([attach_iface/3
         ,attach/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(ethif, {name,
                pid
               }).

-record(state, {ifs = [] :: [#ethif{}],
                arp_cache :: pid(),
                name :: atom()
               }).


%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @spec start_link() -> {ok,Pid} | ignore | {error,Error}
%% @doc Starts the server
%% @end
%%--------------------------------------------------------------------
start_link(Name) ->
    gen_server:start_link({local, Name}, ?MODULE, [Name], []).

start(Name) ->
    gen_server:start({local, Name}, ?MODULE, [Name], []).

attach_iface(Host, Name, StartLinkFn) when is_function(StartLinkFn, 0) ->
    gen_server:call(Host, {attach_iface, Name, StartLinkFn}).

attach(Host, If, AttachFn) when is_function(AttachFn, 1) ->
    gen_server:call(Host, {attach, If, AttachFn}).

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
init([Name]) ->
    {ok, #state{name=Name}}.

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
handle_call({attach_iface, Name, StartLinkFn}, _From,
            State = #state{ifs=IFS}) ->
    case lists:keymember(Name, #ethif.name, IFS) of
        true ->
            {reply, {error, {duplicate_if, Name}}, State};
        false ->
            try StartLinkFn() of
                {ok, Pid} ->
                    {reply, ok, State#state{ifs=[#ethif{name=Name, pid=Pid} | IFS]}};
                Else ->
                    {reply, {error, {if_failed, Else}}, State}
            catch
                Type:Error ->
                    {reply, {error, {if_failed, {Type, Error}}}, State}
            end
    end;

handle_call({attach, If, AttachFn}, _From,
            State = #state{ifs=IFS}) ->
    case lists:keyfind(If, #ethif.name, IFS) of
        #ethif{name=If, pid=Pid} ->
            try AttachFn(Pid) of
                R = {ok, _Pid} ->
                    {reply, R, State};
                Else ->
                    {reply, {error, {attach_failed, Else}}, State}
            catch
                Type:Error ->
                    {reply, {error, {attach_failed, {Type, Error}}}, State}
            end;
        false ->
            {reply, {error, {no_such_if, If}}, State}
    end;

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
