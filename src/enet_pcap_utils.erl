%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc pcap file utils
%% @end
-module(enet_pcap_utils).
-include("enet_pcap.hrl").
-include("enet_types.hrl").

-export([tcp_packet_array/1
         ,tcp_flows/1
         ,tcp_flow_parts/2
         ,tcp_flow/1
         ,tcp_establishment_times/1
        ]).

-export([read_tcp_stream/2,
         read_tcp_streams/1]).

-type packet_array() :: array(). % array:array({timestamp(), packet()})
-type packet() :: #null{} | #eth{} | #ipv4{} | #ipv6{} | #tcp{}.
-type host_port() :: {ip_address() | undefined, netport() | undefined}.
-type tcp_flow() :: {Src::host_port(), Dst::host_port()}.
-type tcp_idx_part() :: { Flow::tcp_flow(),
                          [ Idx::non_neg_integer() ] }.
-type tcp_stream_idxs() :: {Forward::tcp_idx_part(),
                            Reverse::tcp_idx_part()}.
-type tcp_stream_part() :: { Flow::tcp_flow(),
                             {TS::non_neg_integer(),
                              Stream::binary()} }.
-type tcp_stream() :: {Forward::tcp_stream_part(),
                       Reverse::tcp_stream_part()}.

-spec read_tcp_streams(FileName::string()) -> [tcp_stream()].
read_tcp_streams(File) ->
    {PacketArray, _Count} = tcp_packet_array(File),
    FlowIdxParts = tcp_flows(PacketArray),
    [begin
         {A = {Af,_AIdxs}, B = {Bf,_BIdxs}} =
             tcp_flow_parts(FlowIdxPart, PacketArray),
         {{Af, read_tcp_stream(A, PacketArray)},
          {Bf, read_tcp_stream(B, PacketArray)}}
     end
     || FlowIdxPart <- FlowIdxParts ].

-spec tcp_packet_array(File::string()) -> {packet_array(),
                                           Count::non_neg_integer()}.
tcp_packet_array(File) ->
    enet_pcap:file_foldl(File,
                         fun tcp_pa_fold/3,
                         {array:new(), 0}).

tcp_pa_fold(#pcap_hdr{datalinktype=Link,
                      endianness=Endian},
            #pcap_pkt{ts={S,US},data=P},
            {Array,Cnt}) ->
    Pkt = enet_codec:decode(Link, P, [Link, {endianness, Endian},
                                      ethernet, ipv4, ipv6, tcp]),
    TS = (S * 1000000) + US,
    {array:set(Cnt, {TS, Pkt}, Array), Cnt + 1}.

%% Classifies based on src and dst hosts and ports only. Assumes that
%% a flow isn't re-used within a capture.
-spec tcp_flows(packet_array()) -> [tcp_idx_part()].
tcp_flows(PacketArray) ->
    D = array:foldl(fun tcp_flow_fold/3,
                    dict:new(),
                    PacketArray),
    dict:to_list(D).

tcp_flow_fold(Idx, {_TS,Pkt}, FlowD) ->
    case tcp_flow_sort(Pkt) of
        not_tcp -> FlowD;
        Flow -> dict:append(Flow, Idx, FlowD)
    end.

-spec tcp_flow_sort(Pkt::term()) -> tcp_flow() | 'not_tcp'.
tcp_flow_sort(Pkt) ->
    case tcp_flow(Pkt) of
        not_tcp -> not_tcp;
        {A,B} ->
            {erlang:min(A, B), erlang:max(A, B)}
    end.

-spec tcp_flow_parts(tcp_idx_part(),
                     packet_array()) -> tcp_stream_idxs().
tcp_flow_parts({Forward, Idxs}, PacketArray) ->
    Reverse = tcp_flow_reverse(Forward),
    { {Forward,
       [ I || I <- Idxs,
              tcp_flow(packet(I, PacketArray)) =:= Forward ]},
      {Reverse,
       [ I || I <- Idxs,
              tcp_flow(packet(I, PacketArray)) =:= Reverse ]}
    }.

-spec tcp_flow_reverse(tcp_flow()) -> tcp_flow().
tcp_flow_reverse({A,B}) ->
    {B, A}.

-spec tcp_flow(packet()) -> tcp_flow() | 'not_tcp'.
tcp_flow(#null{type = T, data = Pkt}) when T =:= ipv4;
                                           T =:= ipv6 ->
    tcp_flow(Pkt);
tcp_flow(#eth{type = T, data = Pkt}) when T =:= ipv4;
                                          T =:= ipv6 ->
    tcp_flow(Pkt);
tcp_flow(#ipv4{src=S,
               dst=D,
               proto=tcp,
               data=#tcp{src_port=Sp,
                         dst_port=Dp}}) ->
    tcp_flow(S, Sp, D, Dp);
tcp_flow(#ipv6{src=S,
               dst=D,
               payload=Payload}) ->
    case lists:keyfind(tcp, 1, Payload) of
        #tcp{src_port=Sp,
             dst_port=Dp} ->
            tcp_flow(S, Sp, D, Dp);
        _ -> not_tcp
    end;
tcp_flow(_) -> not_tcp.

-spec tcp_flow(S::ip_address(), SP::port_no(),
               D::ip_address(), DP::port_no()) ->
                      tcp_flow().
tcp_flow(Srcaddr, Srcport, Dstaddr, Dstport) ->
    Src = {Srcaddr, Srcport},
    Dst = {Dstaddr, Dstport},
    {Src, Dst}.

%% Time delta between first two packets of various TCP flows. Should
%% usually be correct unless the initial syn from A->B is
%% retransmitted.
tcp_establishment_times(File) ->
    {PacketArray,_Count} = tcp_packet_array(File),
    Times = [ begin
                  Atime = timestamp(A, PacketArray),
                  Btime = timestamp(B, PacketArray),
                  {Flow, erlang:abs(Atime - Btime)}
              end
              || {Flow, [A, B | _]} <- tcp_flows(PacketArray)],
    lists:reverse(lists:keysort(2, Times)).

%% =====================
%% TCP Stream Reassembly
%% =====================

-spec read_tcp_stream(tcp_idx_part(),
                      packet_array()) ->
                             {StartTS::non_neg_integer(), Stream::binary()}.
read_tcp_stream({{Src, Dst}, [P0Idx | Idxs]}, PacketArray) ->
    {TS, P0} = array:get(P0Idx, PacketArray),
    S0 = rts_init(Src, Dst, TS, P0),
    lists:foldl(fun (Idx, State) ->
                        rts_update(packet(Idx, PacketArray), State)
                end,
                S0,
                Idxs).

-record(tcp_stream, {flow, start_time, isn, data = []}).
rts_init(S, D, TS, P0) ->
    case enet_codec:extract(tcp, P0) of
        #tcp{syn=true, seq_no=ISN, data= <<>>} ->
            #tcp_stream{flow={S,D}, isn=ISN, start_time=TS,
                        data = []};
        Tcp ->
            erlang:error({syn_not_set, Tcp})
    end.

rts_update(P, S0 = #tcp_stream{isn=ISN, data=Acc}) ->
    #tcp{seq_no = S, data = Data} = Pkt = enet_codec:extract(tcp, P),
    RelativeSN = S - ISN,
    S1 = S0#tcp_stream{data = [{RelativeSN, Data} | Acc]},
    case Pkt#tcp.fin orelse Pkt#tcp.rst of
        true ->
            rts_finish(S1);
        false ->
            S1
    end;
rts_update(_, Acc) -> Acc.


rts_finish(#tcp_stream{start_time = TS,
                       data = Data}) ->
    [{1, D0} | OrdData] = lists:reverse(Data),
    {TS,
     lists:foldl(fun ({_, <<>>}, Bin) -> Bin;
                     ({Offset, D}, Bin) ->
                         <<Bin:(Offset - 1)/binary, D/binary>>
                 end,
                 D0,
                 OrdData)}.

-spec packet(Idx::non_neg_integer(),
             Array::packet_array()) -> Packet::term().
packet(Idx, Array) ->
    {_TS, Pkt} = array:get(Idx, Array),
    Pkt.

-spec timestamp(Idx::non_neg_integer(),
                Array::packet_array()) -> Timestamp::non_neg_integer().
timestamp(Idx, Array) ->
    {TS, _Pkt} = array:get(Idx, Array),
    TS.
