%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc pcap file utils
%% @end
-module(enet_pcap_utils).
-include("enet_pcap.hrl").
-include("enet_types.hrl").

-export([tcp_packet_array/1,
         tcp_flows/1]).

tcp_packet_array(File) ->
    enet_pcap:file_foldl(File,
                         fun tcp_pa_fold/3,
                         {array:new(), 1}).

tcp_pa_fold(#pcap_hdr{datalinktype=Link},
            #pcap_pkt{ts={S,US},data=P},
            {Array,Cnt}) ->
    Pkt = enet_codec:decode(Link, P, [ethernet, ipv4, tcp]),
    TS = (S * 1000000) + US,
    {array:set(Cnt, {TS, Pkt}, Array), Cnt + 1}.

tcp_flows(PacketArray) ->
    D = array:foldl(fun tcp_flow_fold/3,
                    dict:new(),
                    PacketArray),
    dict:to_list(D).

tcp_flow_fold(0, undefined, Acc) -> Acc;
tcp_flow_fold(Idx,
              {_TS,
               #eth{data = #ipv4{src=S,
                                 dst=D,
                                 proto=tcp,
                                 data=#tcp{src_port=Sp,
                                           dst_port=Dp}}}},
               FlowD) ->
    Src = {S,Sp},
    Dst = {D,Dp},
    Flow = {erlang:min(Src,Dst),
            erlang:max(Src,Dst)},
    dict:append(Flow, Idx, FlowD).

                                          
