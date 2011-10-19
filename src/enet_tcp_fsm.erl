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
-export([init/0
         ,update/3
         ,reassemble/1
         %% ,finished/1
         %% ,relative_time/2
         ,analyze/2
         ,setup_timing/1
        ]).

-export([combine/1
        ]).

-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================
-type timestamp() :: non_neg_integer().
-type ack_no() :: non_neg_integer().

-record(part, {port :: port_no(),
               isn :: 0..16#ffffffff,
               data = [] :: [{timestamp(), binary()}],
               acks = [] :: [{timestamp(), ack_no()}],
               start_time :: timestamp()
              }).

-record(tcp_stream, {c2s = #part{} :: #part{},
                     s2c = #part{} :: #part{},
                     oddities = [],
                     handshake = absent :: 'present' | 'absent',
                     state = non_existent :: 'non_existent' | 'syn_sent' |
                                             'syn_received' | 'established' |
                                             'closed' | 'error'
                    }).

-spec init() -> #tcp_stream{}.
init() ->
    #tcp_stream{state=non_existent}.

update(TS, #tcp{syn=true, ack=false, data = <<>>,
                src_port=C2S, dst_port=S2C,
                seq_no=C2S_ISN},
       S0 = #tcp_stream{state=non_existent}) ->
    S0#tcp_stream{c2s=#part{port=C2S, isn=C2S_ISN,
                            start_time=TS},
                  s2c=#part{port=S2C},
                  state=syn_sent};

update(TS, #tcp{syn=true, ack=true, data = <<>>,
                src_port=S2C, dst_port=C2S,
                seq_no=S2C_ISN, ack_no=C2S_ACK},
       S0 = #tcp_stream{state=syn_sent,
                        c2s=C2SPart=#part{port=C2S, isn=C2S_ISN},
                        s2c=S2CPart=#part{port=S2C}})
  when C2S_ACK =:= C2S_ISN + 1 ->
    S0#tcp_stream{state=established,
                  handshake=present,
                  c2s=C2SPart#part{acks=[{0, TS}]},
                  s2c=S2CPart#part{isn=S2C_ISN,
                                   start_time=TS}};

update(TS, Pkt = #tcp{syn=false, ack=true, fin=Fin}, S0) ->
    Direction = direction(Pkt, S0),
    update(Direction, TS, Pkt, S0);
update(_TS, #tcp{rst=true}, S0) ->
    finish(S0);

update(TS, Pkt, S0) ->
    erlang:error({wasnt_expecting, TS, Pkt, S0}).

finish(S) ->
    S.


update(c2s, TS, Pkt,
       S0 = #tcp_stream{c2s = C2S,
                        s2c = S2C}) ->
    S0#tcp_stream{c2s = update_data(TS, Pkt, C2S),
                  s2c = update_acks(TS, Pkt, S2C)};
update(s2c, TS, Pkt,
       S0 = #tcp_stream{c2s = C2S,
                        s2c = S2C}) ->
    S0#tcp_stream{c2s = update_acks(TS, Pkt, C2S),
                  s2c = update_data(TS, Pkt, S2C)}.


direction(#tcp{src_port=C2S, dst_port=S2C},
          #tcp_stream{c2s=#part{port=C2S},
                      s2c=#part{port=S2C}}) -> c2s;
direction(#tcp{src_port=S2C, dst_port=C2S},
          #tcp_stream{c2s=#part{port=C2S},
                      s2c=#part{port=S2C}}) -> s2c.

update_acks(TS, #tcp{ack=true, ack_no=AckNo},
            P = #part{isn=ISN, acks=Acks}) ->
    P#part{acks=[{relative_seq_no(AckNo, ISN), TS} | Acks]}.

update_data(TS, #tcp{data=Data, seq_no=SeqNo},
            P = #part{isn=ISN, data=Acc}) when byte_size(Data) > 0->
    P#part{data=[{relative_seq_no(SeqNo, ISN), TS, Data} | Acc]};
update_data(_, _, P) -> P.

%%====================================================================
%% Stream reassembly
%%====================================================================

reassemble(#tcp_stream{c2s=C2S, s2c=S2C}) ->
    {reassemble_part(C2S),
     reassemble_part(S2C)}.

reassemble_part(#part{data=Data}) ->
    lists:foldr(fun reassemble_part/2,
                {<<>>, []},
                Data).

reassemble_part({RSN, TS, Data}, {Stream, Offsets})
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

combine({C2S, S2C}) ->
    lists:sort(fun ({_,_,{A,_}}, {_,_,{B,_}}) ->
                       A =< B
               end,
               C2S ++ S2C).


%%====================================================================
%% Message Analysis.
%%====================================================================


%% -spec analyze(Module::atom(), #tcp_stream{}) ->
%%                      {'error', 'broken_stream'} |
%%                      {[{Message::term(),
%%                         {StartIdx::non_neg_integer(),
%%                          StopIdx::non_neg_integer()},
%%                         {StartTS::non_neg_integer(),
%%                          Duration::non_neg_integer()}}],
%%                       Oddballs::[{Timestamp::non_neg_integer(),
%%                                   'retransmit' | 'missing_packet'}]}.
analyze(_, #tcp_stream{state=error}) ->
    {error, broken_stream};
analyze(Module, #tcp_stream{} = S) ->
    {C2S, S2C} = reassemble(S),
    {analyze(Module, C2S, 0, (S#tcp_stream.c2s)#part.acks),
     analyze(Module, S2C, 0, (S#tcp_stream.s2c)#part.acks)}.

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
    EndTS = earliest_ack(StopIdx, Relacks),
    {StartTS, EndTS - StartTS}.

earliest_offset(StartIdx, Offsets) ->
    lists:min([TS || {TS, _, I, J} <- Offsets,
                     I =< StartIdx,
                     StartIdx =< J]).

latest_ack(StopIdx, Relacks) ->
    EarliestAck = lists:min([ Ack || {Ack, _} <- Relacks,
                                     Ack >= StopIdx ]),
    lists:max([ TS || {Ack, TS} <- Relacks,
                      Ack =:= EarliestAck]).

earliest_ack(Idx, Relacks) ->
    EarliestAck = lists:min([ Ack || {Ack, _} <- Relacks,
                                     Ack >= Idx ]),
    lists:min([ TS || {Ack, TS} <- Relacks,
                      Ack =:= EarliestAck]).

%%====================================================================
%% Timing
%%====================================================================

syn_ts(#tcp_stream{c2s=#part{start_time=T0}}) ->
    T0.

synack_ts(#tcp_stream{c2s=#part{acks=Acks}}) ->
    lists:max([ TS || {0, TS} <- Acks]).

twh_ts(#tcp_stream{s2c=#part{acks=Acks}}) ->
    lists:min([ TS || {1, TS} <- Acks]).

setup_timing(S = #tcp_stream{}) ->
    SynTS = syn_ts(S),
    SynAckTS = synack_ts(S),
    HandshakeTS = twh_ts(S),
    {SynTS, SynAckTS - SynTS, HandshakeTS - SynTS}.

%%====================================================================
%% Internal functions
%%====================================================================

relative_seq_no(S, ISN) when S < ISN ->
    (16#ffffffff - ISN) + S;
relative_seq_no(S, ISN) ->
    S - ISN.
