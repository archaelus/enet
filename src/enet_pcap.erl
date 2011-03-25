%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Pcap file format library
%% @end
-module(enet_pcap).

-include_lib("kernel/include/file.hrl").
-include("enet_pcap.hrl"). 

-export([foreach_file_packets/2
         ,read_file/1
         ,read_file/2
         ,file_foldl/3
         ]).

-export([ decode_header/1
         ,encode_header/1
         ,default_header/0
         ,decode_packet/1
         ,encode_packet/2
         ,append_to_file/2
        ]).

%% Example:
%% enet_pcap:foreach_file_packets("misc/http_txn.pcap",
%%                                fun (#pcap_hdr{datalinktype=T},
%%                                     #pcap_pkt{ts={TS,US},data=P}) ->
%%                                        {{Y,M,D},{H,Min,S}} = enet_pcap:ts_to_localtime(TS),
%%                                        io:format("~p-~p-~p ~p:~p:~p.~p Packet: ~p~nFrame:~n~p~n~n",
%%                                                  [Y,M,D,H,Min,S,US,
%%                                                   catch enet_codec:decode(T, P, [all]),
%%                                                   P])
%%                                end).


%%====================================================================
%% API
%%====================================================================

read_file(FileName) ->
    file_foldl(FileName,
               fun (_Header, Packet, Acc) ->
                       [Packet | Acc]
               end,
               []).

read_file(FileName, Opts) ->
    case proplists:get_value(headers, Opts) of
        true ->
            file_foldl(FileName,
                       fun (Header, Packet, {_,Acc}) ->
                               {Header,[Packet | Acc]}
                       end,
                       {undefined,[]});
        false ->
            read_file(FileName)
    end.


file_foldl(FileName, FoldFun, Acc0)
  when is_function(FoldFun, 3) ->
    {ok, File} = file:open(FileName, [binary, read, raw]),
    {ok, Hdr} = file:read(File, ?PCAP_HDR_SIZE),
    {Header, <<>>} = decode_header(Hdr),
    Acc = file_foldl(Header, File, FoldFun, Acc0),
    file:close(File),
    Acc.

file_foldl(Header, File, FoldFun, Acc0)
  when is_function(FoldFun, 3) ->
    case read_one_packet(Header, File) of
        eof -> Acc0;
        {ok, Packet} ->
            Acc = FoldFun(Header, Packet, Acc0),
            file_foldl(Header, File, FoldFun, Acc)
    end.

foreach_file_packets(Filename, Fun) when is_function(Fun) ->
    {ok, File} = file:open(Filename, [binary, read, raw]),
    {ok, Hdr} = file:read(File, ?PCAP_HDR_SIZE),
    {Header, <<>>} = decode_header(Hdr),
    foreach_file_packets(Header, File, Fun),
    file:close(File).

foreach_file_packets(Header, File, Fun) ->
    case read_one_packet(Header, File) of
        eof -> ok;
        {ok, Packet} ->
            Fun(Header, Packet),
            foreach_file_packets(Header, File, Fun)
    end.

read_one_packet(#pcap_hdr{endianess=little}, File) ->
    case file:read(File, ?PCAP_PKTHDR_SIZE) of
        eof -> eof;
        {ok, <<TS_Secs:32/little,
               TS_USecs:32/little,
               PktLen:32/little,
               OrigLen:32/little>>} ->
            {ok, PktData} = file:read(File, PktLen),
            {ok, #pcap_pkt{ts={TS_Secs, TS_USecs},
                           orig_len=OrigLen,
                           data=PktData}}
    end.

append_to_file(Pkt = #pcap_pkt{}, FileName) ->
    {_, Hdr, F} = open_file(FileName),
    {ok, _} = file:position(F, eof),
    ok = file:write(F, encode_packet(Hdr, Pkt)),
    file:close(F);
append_to_file(Packet, FileName) when is_binary(Packet) ->
    append_to_file(#pcap_pkt{ts=now_to_ts(),
                             orig_len=byte_size(Packet),
                             data=Packet},
                   FileName).

open_file(FileName) ->
    {ok, F} = file:open(FileName, [raw, binary, read, append]),
    case file:read_file_info(FileName) of
        {ok, #file_info{size=0}} ->
            Hdr = default_header(),
            ok = file:write(F, encode_header(Hdr)),
            {created, Hdr, F};
        {ok, #file_info{size=Sz}}
          when Sz >= ?PCAP_HDR_SIZE ->
            {opened, read_header(F), F}
    end.

read_header(F) ->
    {ok, _} = file:position(F, bof),
    {ok, BHdr} = file:read(F, ?PCAP_HDR_SIZE),
    {Hdr, <<>>} = decode_header(BHdr),
    Hdr.

%%====================================================================
%% PCAP timestamp conversion functions
%%====================================================================

ts_to_datetime(#pcap_pkt{ts=Ts}) -> ts_to_datetime(Ts);
ts_to_datetime({UnixTS, _MicroSecs}) when is_integer(UnixTS) ->
    unix_ts_to_datetime(UnixTS);
ts_to_datetime(UnixTS) when is_integer(UnixTS) ->
    unix_ts_to_datetime(UnixTS).

ts_to_localtime(T) ->
    calendar:universal_time_to_local_time(ts_to_datetime(T)).

ts_to_now(#pcap_pkt{ts=Ts}) -> ts_to_now(Ts);
ts_to_now({UnixTS, MicroSecs}) ->
    {UnixTS div 1000000,
     UnixTS rem 1000000,
     MicroSecs}.

now_to_ts() ->
    now_to_ts(erlang:now()).
now_to_ts({Mega, Secs, Micros}) ->
    {Mega * 1000000 + Secs,
     Micros}.

unix_ts_to_datetime(Ts) when is_list(Ts) ->
    unix_ts_to_datetime(list_to_integer(Ts));
unix_ts_to_datetime(Ts) when is_integer(Ts) ->
    Ts1970 = calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    calendar:gregorian_seconds_to_datetime(Ts1970 + Ts).

%%====================================================================
%% PCAP Header parser/generator
%%====================================================================
decode_header(<<16#d4,16#c3,16#b2,16#a1,
              VersionMajor:16/little,
              VersionMinor:16/little,
              TzCorrection:32/signed-little,
              SigFigures:32/little,
              SnapLen:32/little,
              DataLinkType:32/little,
              Rest/binary>>) ->
    {#pcap_hdr{version={VersionMajor, VersionMinor},
               tz_correction=TzCorrection,
               sigfigures=SigFigures,
               snaplen=SnapLen,
               datalinktype=decode_linktype(DataLinkType),
               endianess=little},
     Rest};
decode_header(<<16#a1,16#b2,16#c3,16#d4,
              VersionMajor:16/big,
              VersionMinor:16/big,
              TzCorrection:32/signed-big,
              SigFigures:32/big,
              SnapLen:32/big,
              DataLinkType:32/big,
              Rest/binary>>) ->
    {#pcap_hdr{version={VersionMajor, VersionMinor},
               tz_correction=TzCorrection,
               sigfigures=SigFigures,
               snaplen=SnapLen,
               datalinktype=decode_linktype(DataLinkType),
               endianess=big},
     Rest}.

default_header() ->
    #pcap_hdr{version={2, 4},
              tz_correction=0,
              sigfigures=0,
              snaplen=65535,
              datalinktype=1,
              endianess=little}.

encode_header(#pcap_hdr{version={VersionMajor, VersionMinor},
                        tz_correction=TzCorrection,
                        sigfigures=SigFigures,
                        snaplen=SnapLen,
                        datalinktype=DataLinkType,
                        endianess=little}) ->
    <<16#d4,16#c3,16#b2,16#a1,
     VersionMajor:16/little,
     VersionMinor:16/little,
     TzCorrection:32/signed-little,
     SigFigures:32/little,
     SnapLen:32/little,
     (encode_linktype(DataLinkType)):32/little>>;
encode_header(#pcap_hdr{version={VersionMajor, VersionMinor},
                        tz_correction=TzCorrection,
                        sigfigures=SigFigures,
                        snaplen=SnapLen,
                        datalinktype=DataLinkType,
                        endianess=big}) ->
    <<16#a1,16#b2,16#c3,16#d4,
     VersionMajor:16/big,
     VersionMinor:16/big,
     TzCorrection:32/signed-big,
     SigFigures:32/big,
     SnapLen:32/big,
     (encode_linktype(DataLinkType)):32/big>>.


%%====================================================================
%% PCAP packet parser/generator
%%====================================================================

decode_packet({#pcap_hdr{endianess=Endianess}, Data}) ->
    decode_packet(Endianess, Data).

decode_packet(#pcap_hdr{endianess=Endianess}, Data) ->
    decode_packet(Endianess, Data);
decode_packet(little,
              <<TS_Secs:32/little,
                TS_USecs:32/little,
                PktLen:32/little,
                OrigLen:32/little,
                Data:PktLen/binary,
                RestPacket/binary>>) ->
    Pcap = #pcap_pkt{ts={TS_Secs,TS_USecs},orig_len=OrigLen},
    {Pcap,Data,RestPacket};
decode_packet(big,
              <<TS_Secs:32/big,
                TS_USecs:32/big,
                PktLen:32/big,
                OrigLen:32/big,
                Data:PktLen/binary,
                RestPacket/binary>>) ->
    Pcap = #pcap_pkt{ts={TS_Secs,TS_USecs},orig_len=OrigLen},
    {Pcap,Data,RestPacket}.

generate_pcap_packet_header(TS_Secs,TS_USecs,OrigLen,Data) ->
    encode_packet(little,
                  #pcap_pkt{ts={TS_Secs,TS_USecs},
                            orig_len=OrigLen,
                            data=Data}).
encode_packet(#pcap_hdr{endianess=End}, #pcap_pkt{} = P) ->
    encode_packet(End, P);
encode_packet(little, #pcap_pkt{ts={TS_Secs,TS_USecs},
                                orig_len=OrigLen,
                                data=Data}) ->
    DataSize = byte_size(Data),
    <<TS_Secs:32/little,
     TS_USecs:32/little,
     DataSize:32/little,
     OrigLen:32/little,
     Data/binary>>;
encode_packet(big, #pcap_pkt{ts={TS_Secs,TS_USecs},
                             orig_len=OrigLen,
                             data=Data}) ->
    DataSize = byte_size(Data),
    <<TS_Secs:32/big,
     TS_USecs:32/big,
     DataSize:32/big,
     OrigLen:32/big,
     Data/binary>>.


decode_linktype(0) -> null;
decode_linktype(1) -> ethernet;
decode_linktype(N) when is_integer(N) -> N.

encode_linktype(N) when is_integer(N) -> N;
encode_linktype(null) -> 0;
encode_linktype(ethernet) -> 1.
