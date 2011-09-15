%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc TCP stream finite state machine.
%% @end
%%%-------------------------------------------------------------------
-module(enet_tcp_fsm).

%% API
-export([init/2
         ,update/3
         ,reassemble/1
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
                     state = closed :: 'closed' | 'established' | 'error'
                    }).

-spec init(TS::non_neg_integer(), #tcp{}) -> #tcp_stream{}.
init(TS, #tcp{syn=true, seq_no=ISN, data= D}) ->
    #tcp_stream{isn=ISN, start_time=TS,
                data = [{0, TS, D}],
                state = established}.

update(TS, Pkt = #tcp{seq_no = S, data = Data},
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

reassemble({0, TS, Data}, {<<>>, []}) ->
    {Data, [{TS, syn, 0, 0}]};
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

%%====================================================================
%% Internal functions
%%====================================================================
