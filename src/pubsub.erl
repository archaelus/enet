%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Plain Old Erlang publish/subscribe
%% @end
%%%-------------------------------------------------------------------
-module(pubsub).

%% API
-export([new/0
         ,add_subscriber/2
         ,remove_subscriber/2
         ,process_msg/2
         ,send/2
        ]).

-export([sync_subscribe/1
         ,sync_unsubscribe/1
        ]).

-record(pubsub, {subscribers = []}).
-define(FILTER_ALL, all).
-record(sub, {pid :: pid(),
              filter = ?FILTER_ALL :: function() | 'all'
             }).

-include_lib("eunit/include/eunit.hrl").

-opaque pubsub() :: #pubsub{}.

%%====================================================================
%% API
%%====================================================================

new() ->
    #pubsub{}.

sync_subscribe(Publisher) ->
    gen_server:call(Publisher, {?MODULE, {sub, self()}}).

sync_unsubscribe(Publisher) ->
    gen_server:call(Publisher, {?MODULE, {unsub, self()}}).

add_subscriber(Pid, P = #pubsub{}) when is_pid(Pid) ->
    add_subscriber(Pid, ?FILTER_ALL, P).

add_subscriber(Pid, Fn, P = #pubsub{subscribers=Subs})
  when is_pid(Pid),
       Fn =:= ?FILTER_ALL; is_function(Fn, 1) ->
    case subscribed(Pid, P) of
        false ->
            P#pubsub{subscribers=[#sub{pid=Pid} | Subs]};
        true ->
            P
    end.

remove_subscriber(Pid, P = #pubsub{subscribers=Subs}) when is_pid(Pid) ->
    P#pubsub{subscribers=lists:keydelete(Pid, #sub.pid, Subs)}.

process_msg({sub, Pid}, P = #pubsub{}) ->
    add_subscriber(Pid, P);
process_msg({unsub, Pid}, P = #pubsub{}) ->
    remove_subscriber(Pid, P);
process_msg({'DOWN', _, _, Pid, _}, P) ->
    remove_subscriber(Pid, P).

send(Message, #pubsub{subscribers=Subs}) ->
    [ Pid ! Message
      || #sub{pid=Pid, filter=Fn} <- Subs,
         Fn =:= ?FILTER_ALL orelse
         Fn(Message) ],
    ok.

subscribed(Pid, #pubsub{subscribers=Subs}) when is_pid(Pid) ->
    lists:keymember(Pid, #sub.pid, Subs).

%%====================================================================
%% Internal functions
%%====================================================================

sub_test() ->
    P1 = new(),
    Pid = self(),
    P2 = process_msg({sub, Pid}, P1),
    ?assertMatch(true, subscribed(Pid, P2)),
    P3 = process_msg({sub, Pid}, P2),
    ?assert(P3 =:= P2),
    P4 = process_msg({unsub, Pid}, P3),
    ?assert(P4 =:= P1),
    P5 = process_msg({'DOWN', foo, foo, Pid, foo}, P2),
    ?assert(P5 =:= P1).
