%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc
%% @end
%%%-------------------------------------------------------------------
-module(enet_bertrpc_fsm).

%% -compile(native).

%% API
-export([init/0
         ,update/2
         ,analyze/1
        ]).

-record(cmd, {type :: 'call' | 'cast',
              mfa :: {atom(), atom(), non_neg_integer()},
              req, resp,
              timing}).

-record(bertrpc, {current = queue:new() :: queue:queue(#cmd{}) | 'undefined',
                  commands = [] :: list()}).

%%====================================================================
%% API
%%====================================================================

init() ->
    #bertrpc{}.

update({{Type, M, F, A}, _, _} = Req, FSM = #bertrpc{current=Q})
  when Type =:= call; Type =:= cast ->
    Cmd = #cmd{type=Type, req=Req,
               mfa={M,F,length(A)}},
    FSM#bertrpc{current=queue:in(Cmd, Q)};
update({{noreply},_,_} = Resp,
       FSM = #bertrpc{current = Q0}) ->
    case queue:out(Q0) of
        {{value, Cmd = #cmd{type=cast}}, Q} ->
            complete_op(Cmd#cmd{resp=Resp}, FSM#bertrpc{current=Q});
        {{value, Cmd}, Q} ->
            erlang:error({incorrect_response, Cmd, Resp});
            %% error -- incorrect request for response
            %% FSM#bertrpc{current=Q};
        {empty, Q} ->
            %% error -- no request for response
            %%FSM#bertrpc{current=Q}
            erlang:error({no_request, Resp})
    end;
update({{reply, _},_,_} = Resp,
       FSM = #bertrpc{current = Q0}) ->
    case queue:out(Q0) of
        {{value, Cmd = #cmd{type=call}}, Q} ->
            complete_op(Cmd#cmd{resp=Resp}, FSM#bertrpc{current=Q});
        {{value, Cmd}, Q} ->
            erlang:error({incorrect_response, Cmd, Resp});
            %% error -- incorrect request for response
            %% FSM#bertrpc{current=Q};
        {empty, Q} ->
            %% error -- no request for response
            %%FSM#bertrpc{current=Q}
            erlang:error({no_request, Resp})
    end;
update(Thing, FSM) ->
    erlang:error({Thing, FSM}).



complete_op(Cmd, FSM = #bertrpc{commands=Cmds}) ->
    FSM#bertrpc{commands=[Cmd | Cmds]}.

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
    {Type, MFA, Start, CommandDuration, ServerTime}.

%%====================================================================
%% Internal functions
%%====================================================================
