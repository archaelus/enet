%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc TCP stream finite state machine.
%% @end
%%%-------------------------------------------------------------------
-module(enet_tcp_fsm).

-compile(native).

%% API
-export([init/2
         ,update/3
         ,reassemble/1
         ,finished/1
         ,relative_time/2
         ,analyze/2
        ]).

-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

-record(tcp_stream, {start_time :: non_neg_integer(),
                     isn :: 0..4294967295,
                     %% Data holds packets in reverse order.
                     data = [] :: [{RSN::non_neg_integer(),
                                    TS::non_neg_integer(),
                                    Data::binary()}],
                     state = closed :: 'closed' | 'established' |
                                       'error' | 'finished'
                    }).

-spec init(TS::non_neg_integer(), #tcp{}) -> #tcp_stream{}.
init(TS, #tcp{syn=true, seq_no=ISN, data= D}) ->
    #tcp_stream{isn=ISN, start_time=TS,
                data = [{0, TS, D}],
                state = established};
init(_TS, #tcp{}) ->
    #tcp_stream{state = error}.


update(TS, Pkt = #tcp{seq_no = S, data = Data, ack = true},
       S0 = #tcp_stream{isn=ISN,
                        data=Acc, state=established}) ->
    RelativeSN = S - ISN,
    S1 = S0#tcp_stream{data = [{RelativeSN, TS, Data} | Acc]},
    case Pkt#tcp.fin orelse Pkt#tcp.rst of
        true ->
            S1#tcp_stream{state=finished};
        false ->
            S1
    end;
%% XXX - should warn about packets in other states.
update(_TS, _Pkt, Stream = #tcp_stream{}) -> Stream.


reassemble(#tcp_stream{data = Data}) ->
    %% foldr because the packet list in Data needs to be reversed
    lists:foldr(fun reassemble/2,
                {<<>>, []},
                Data).

-type tcp_segment() :: {RSN::non_neg_integer(),
                        Timestamp::non_neg_integer(),
                        Data::binary()}.

-type offset_data() :: {Timestamp::non_neg_integer(),
                        'syn' | 'normal' | 'retransmit' | 'missing_packet',
                        StartIdx::non_neg_integer(),
                        StopIdx::non_neg_integer()}.

-spec reassemble(tcp_segment(), {Data::binary(), [offset_data()]}) ->
                        {Data::binary(), [offset_data()]}.
reassemble({0, TS, Data}, {<<>>, []}) ->
    {Data, [{TS, syn, 0, 0}]};
reassemble({RSN, TS, Data}, {Stream, Offsets})
  when is_integer(RSN), is_integer(TS),
       is_binary(Data), is_binary(Stream),
       is_list(Offsets) ->
    TargetSN = byte_size(Stream) + 1,
    if TargetSN =:= RSN ->
            {<<Stream/binary, Data/binary>>,
             [{TS, normal, RSN - 1, RSN+byte_size(Data) - 1} | Offsets]};
       RSN < TargetSN ->
            {<<Stream:(RSN - 1)/binary, Data/binary>>,
             [{TS, retransmit, RSN - 1, RSN+byte_size(Data) - 1} | Offsets]};
       RSN > TargetSN ->
            DataOffset = RSN - TargetSN,
            {<<Stream/binary, 0:DataOffset/integer-unit:8, Data/binary>>,
             [{TS, missing_packet, DataOffset,
               DataOffset+byte_size(Data)} | Offsets]}
    end.

finished(#tcp_stream{state=S}) -> S =:= finished.

relative_time(TS, #tcp_stream{start_time=T0}) ->
    TS - T0.

-spec analyze(Module::atom(), #tcp_stream{}) ->
                     {'error', 'broken_stream'} |
                     {[{Message::term(),
                        {StartIdx::non_neg_integer(),
                         StopIdx::non_neg_integer()},
                        {StartTime::non_neg_integer(),
                         Duration::non_neg_integer()}}],
                      Oddballs::[{Timestamp::non_neg_integer(),
                                  'retransmit' | 'missing_packet'}]}.
analyze(_, #tcp_stream{state=error}) ->
    {error, broken_stream};
analyze(Module, #tcp_stream{} = S) ->
    Stream = {_, Offsets} = reassemble(S),
    {analyze_timings(Module, Stream, 0),
     oddballs(Offsets)}.

analyze_timings(Module, {Stream, Offsets}, Idx) when Idx < byte_size(Stream) ->
    <<_:Idx/binary, Buf/binary>> = Stream,
    case Module:decode(Buf) of
        {complete, Term, Rest} ->
            NewIdx = byte_size(Stream) - byte_size(Rest),
            IdxRange = {Idx, NewIdx - 1},
            [{Term, IdxRange, analyze_timing(IdxRange, Offsets)}
             | analyze_timings(Module, {Stream, Offsets}, NewIdx)];
        {partial, _BytesNeeded} ->
            IdxRange = {Idx, byte_size(Stream)},
            [{partial, IdxRange, analyze_timing(IdxRange, Offsets)}]
    end;
analyze_timings(_, _, _) -> [].

analyze_timing({StartIdx, StopIdx}, Offsets) ->
    StartTS = lists:min(ts_range(StartIdx, Offsets)),
    EndTS = lists:max(ts_range(StopIdx, Offsets)),
    {StartTS, EndTS - StartTS}.

ts_range(Idx, Offsets) ->
    [ TS || {TS, _, I, J} <- Offsets,
            I =< Idx,
            Idx =< J ].

oddballs(Offsets) ->
    [ {TS, Type} || {TS, Type, _, _} <- Offsets,
                    Type =/= normal, Type =/= syn ].
%%====================================================================
%% Internal functions
%%====================================================================
