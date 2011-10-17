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
         ,analyze/3
         ,acks/1
        ]).

-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

-record(tcp_stream, {start_time :: non_neg_integer(),
                     isn :: 0..4294967295,
                     port :: port_no(),
                     %% Data holds packets in reverse order.
                     data = [] :: [{RSN::non_neg_integer(),
                                    TS::non_neg_integer(),
                                    Data::binary()}],
                     acks = [] :: [{AckNo::non_neg_integer(),
                                    TS::non_neg_integer()}],
                     state = closed :: 'closed' | 'established' |
                                       'error' | 'finished',
                     role :: 'client' | 'server'
                    }).

-spec init(TS::non_neg_integer(), #tcp{}) -> #tcp_stream{}.
init(TS, #tcp{syn=true, ack=false,
              src_port=Port,
              seq_no=ISN,
              data= <<>>}) ->
    #tcp_stream{isn=ISN, start_time=TS,
                port=Port,
                data = [],
                state = established,
                role = client};
init(TS, Pkt = #tcp{syn=true, ack=true,
                    src_port=Port,
                    seq_no=ISN,
                    data= <<>>}) ->
    S = #tcp_stream{isn=ISN, start_time=TS,
                    port=Port,
                    data = [],
                    state = established,
                    role = server},
    update_acks(TS, Pkt, S);
init(_TS, #tcp{}) ->
    #tcp_stream{state = error}.


update(TS, Pkt = #tcp{},
       S0 = #tcp_stream{state=established}) ->
    S1 = update_acks(TS, Pkt, S0),
    S2 = update_data(TS, Pkt, S1),
    maybe_finish(TS, Pkt, S2);
update(TS, Pkt = #tcp{},
       S = #tcp_stream{state=finished}) ->
    update_acks(TS, Pkt, S);
update(TS, Pkt, S) ->
    erlang:error({bad_update, TS, Pkt, S}).


update_acks(TS, #tcp{ack=true, ack_no=AckNo},
            S = #tcp_stream{acks=Acks}) ->
    S#tcp_stream{acks=[{AckNo, TS} | Acks]}.

update_data(TS, #tcp{ack=true, seq_no=SeqNo, data = Data},
            S = #tcp_stream{isn=ISN, data=Acc})
  when Data =/= <<>> ->
    RelativeSN = SeqNo - ISN,
    S#tcp_stream{data = [{RelativeSN, TS, Data} | Acc]};
update_data(_TS, _PKT, S) -> S.

maybe_finish(_TS, #tcp{fin=Fin, rst=Rst},
             S = #tcp_stream{state=established}) when Fin; Rst ->
    S#tcp_stream{state=finished};
maybe_finish(_, _, S) -> S.


reassemble(#tcp_stream{start_time=TS, data = Data}) ->
    %% foldr because the packet list in Data needs to be reversed
    lists:foldr(fun reassemble/2,
                {<<>>, [{TS, syn, 0, 0}]},
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
reassemble({RSN, RTS, Data}, {Stream, Offsets})
  when is_integer(RSN), is_integer(RTS),
       is_binary(Data), is_binary(Stream),
       is_list(Offsets) ->
    TargetSN = byte_size(Stream) + 1,
    if TargetSN =:= RSN ->
            {<<Stream/binary, Data/binary>>,
             [{RTS, normal, RSN - 1, RSN+byte_size(Data) - 1} | Offsets]};
       RSN < TargetSN ->
            {<<Stream:(RSN - 1)/binary, Data/binary>>,
             [{RTS, retransmit, RSN - 1, RSN+byte_size(Data) - 1} | Offsets]};
       RSN > TargetSN ->
            DataOffset = RSN - TargetSN,
            {<<Stream/binary, 0:DataOffset/integer-unit:8, Data/binary>>,
             [{RTS, missing_packet, DataOffset,
               DataOffset+byte_size(Data)} | Offsets]}
    end.

finished(#tcp_stream{state=S}) -> S =:= finished.

acks(#tcp_stream{acks=Acks}) -> Acks.

relative_time(TS, #tcp_stream{start_time=T0}) ->
    TS - T0.

-spec analyze(Module::atom(), #tcp_stream{}, [{Ack::non_neg_integer(),
                                               TS::non_neg_integer()}]) ->
                     {'error', 'broken_stream'} |
                     {[{Message::term(),
                        {StartIdx::non_neg_integer(),
                         StopIdx::non_neg_integer()},
                        {StartTS::non_neg_integer(),
                         Duration::non_neg_integer()}}],
                      Oddballs::[{Timestamp::non_neg_integer(),
                                  'retransmit' | 'missing_packet'}]}.
analyze(_, #tcp_stream{state=error}, _Acks) ->
    {error, broken_stream};
analyze(Module, #tcp_stream{} = S, Acks) ->
    Relacks = relative_acks(Acks, S),
    Stream = {_, Offsets} = reassemble(S),
    {analyze(Module, Stream, 0, Relacks),
     oddballs(Offsets)}.

analyze(Module, {Stream, Offsets}, Idx, Relacks) when Idx < byte_size(Stream) ->
    <<_:Idx/binary, Buf/binary>> = Stream,
    case Module:decode(Buf) of
        {complete, Term, Rest} ->
            NewIdx = byte_size(Stream) - byte_size(Rest),
            IdxRange = {Idx, NewIdx - 1},
            [{Term, IdxRange, analyze_timing(IdxRange, Offsets, Relacks)}
             | analyze(Module, {Stream, Offsets}, NewIdx, Relacks)];
        {partial, _BytesNeeded} ->
            IdxRange = {Idx, byte_size(Stream)},
            [{partial, IdxRange, analyze_timing(IdxRange, Offsets, Relacks)}]
    end;
analyze(_, _, _, _) -> [].

oddballs(Offsets) ->
    [ {TS, Type} || {TS, Type, _, _} <- Offsets,
                    Type =/= normal, Type =/= syn ].

analyze_timing({StartIdx, StopIdx}, Offsets, Relacks) ->
    StartTS = earliest_offset(StartIdx, Offsets),
    EndTS = latest_ack(StopIdx, Relacks),
    {StartTS, EndTS - StartTS}.

earliest_offset(StartIdx, [{TS, _, I, J} | _])
  when I =< StartIdx,
       StartIdx =< J -> TS;
earliest_offset(StartIdx, [_ | Rest]) ->
    earliest_offset(StartIdx, Rest).

latest_ack(StopIdx, Relacks) ->
    MinAck = hd([ Ack || {Ack, _} <- Relacks,
                         Ack >= StopIdx ]),
    lists:max([ TS || {Ack, TS} <- Relacks,
                      Ack =:= MinAck]).

%%====================================================================
%% Internal functions
%%====================================================================

relative_acks(Acks, #tcp_stream{isn=ISN}) ->
    [{case AckNo > ISN of
          true -> AckNo - ISN;
          false -> AckNo + 16#ffffffff - ISN
      end, TS}
     || {AckNo, TS} <- Acks].
