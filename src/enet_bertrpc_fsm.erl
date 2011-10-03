%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc
%% @end
%%%-------------------------------------------------------------------
-module(enet_bertrpc_fsm).

-compile(native).

%% API
-export([init/0
         ,update/2
         ,analyze/1
        ]).

-record(cmd, {type :: 'call' | 'cast',
              mfa :: {atom(), atom(), non_neg_integer()},
              req, resp,
              timing}).

-record(bertrpc, {current = undefined :: #cmd{} | 'undefined',
                  commands = [] :: list()}).

%%====================================================================
%% API
%%====================================================================

init() ->
    #bertrpc{}.

update({{Type, M, F, A}, _, _} = Req, FSM = #bertrpc{current=undefined})
  when Type =:= call; Type =:= cast ->
    FSM#bertrpc{current=#cmd{type=Type, req=Req,
                             mfa={M,F,length(A)}}};
update({{noreply},_,_} = Resp,
       FSM = #bertrpc{current = Cmd = #cmd{type=cast}}) ->
    complete_op(Cmd#cmd{resp=Resp}, FSM);
update({{reply, _},_,_} = Resp,
       FSM = #bertrpc{current = Cmd = #cmd{type=call}}) ->
    complete_op(Cmd#cmd{resp=Resp}, FSM);
update({_, _, _}, FSM = #bertrpc{current=undefined}) ->
    %% XXX actually an error.
    FSM.


complete_op(Cmd, FSM = #bertrpc{commands=Cmds}) ->
    FSM#bertrpc{commands=[Cmd | Cmds], current=undefined}.

-type timestamp() :: non_neg_integer().
-type duration() :: integer().

-spec analyze(#bertrpc{}) -> [{Type :: 'call' | 'cast',
                               MFA :: {atom(), atom(), non_neg_integer()},
                               Start::timestamp(),
                               End::timestamp(),
                               Duration::duration(),
                               ServerTime::duration()}].
analyze(#bertrpc{commands=RCmds}) ->
    Cmds = lists:reverse(RCmds),
    [ analyze_command(Cmd) || Cmd <- Cmds ].

analyze_command(#cmd{type=Type,
                     mfa=MFA,
                     req={_R, _ByteInfo, {Start, Duration}},
                     resp={_Resp, _RByteInfo, {Stop, RDuration}}}) ->
    End = Stop+RDuration,
    CommandDuration = End - Start,
    ServerTime = Stop - Start - Duration,
    {Type, MFA, Start, End, CommandDuration, ServerTime}.

%%====================================================================
%% Internal functions
%%====================================================================
