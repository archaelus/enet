%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc TCP codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_tcp).

%% API
-export([decode/2
         ,decode_port/1
         ,encode_port/1]).

-include("types.hrl").
-define(TCP_HEADER_MIN_LEN, 20).

%%====================================================================
%% API
%%====================================================================

decode(<<Src:16/big, Dst:16/big,
        Sequence:32/big, Ack:32/big,
        DataOffset:4, Reserved:6,
        Urg:1, Ack:1, Psh:1, Rst:1, Syn:1, Fin:1,
        Window:16/big,
        Csum:16/big, UrgPointer:16/big,
        Data/binary>> = Pkt,
       [IPH = #ipv4_pseudo_hdr{} | DecodeOpts]) ->
    HeaderLen = 4*DataOffset,
    OptsLen = HeaderLen - ?TCP_HEADER_MIN_LEN,
    << _Header:20/binary,
     Options:OptsLen/binary,
     TcpData/binary>> = Pkt,
    Tcp = #tcp{src_port=decode_port(Src)
               ,dst_port=decode_port(Dst)
               ,seq_no=Sequence
               ,ack_no=Ack
               ,data_offset=DataOffset
               ,reserved=Reserved
               ,urg=decode_flag(Urg), ack=decode_flag(Ack), psh=decode_flag(Psh)
               ,rst=decode_flag(Rst), syn=decode_flag(Syn), fin=decode_flag(Fin)
               ,window=Window
               ,csum=check_sum(Csum, IPH, byte_size(Pkt), Pkt)
               ,urg_pointer=UrgPointer
               ,options=decode_options(Options)
               ,data=TcpData
              };
decode(_Packet, _DecodeOpts) ->
    {error, bad_packet}.

decode_port(Port) ->
    enet_services:decode_port(tcp, Port).

encode_port(Port) ->
    enet_services:encode_port(tcp, Port).

%%====================================================================
%% Internal functions
%%====================================================================

decode_flag(0) -> false;
decode_flag(1) -> true.

decode_options(Blob) ->
    decode_options(Blob, []).

decode_options(<<>>, Acc) ->
    lists:reverse(Acc);
%% End of Options List (padding?)
decode_options(<<0, Rest/binary>>, Acc) -> decode_options(Rest, Acc);
%% Nop
decode_options(<<1, Rest/binary>>, Acc) -> decode_options(Rest, Acc);
%% MSS
decode_options(<<2, 4, MSS:16/big, Rest/binary>>, Acc) ->
    decode_options(Rest, [{mss, MSS} | Acc]);
%% Window Size Shift
decode_options(<<3, 3, Shift, Rest/binary>>, Acc) ->
    decode_options(Rest, [{window_size_shift, Shift} | Acc]);
%% SACK Permitted
decode_options(<<4, 2, Rest/binary>>, Acc) ->
    decode_options(Rest, [sack_ok | Acc]);
%% SACK
decode_options(<<5, Len, Tail/binary>>, Acc) ->
    SackLen = Len - 2,
    <<SackData:SackLen/binary, Rest/binary>> = Tail,
    decode_options(Rest, [{sack, SackData} | Acc]);
decode_options(<<8, 10, TSVal:32, TSReply:32, Rest/binary>>, Acc) ->
    decode_options(Rest, [{timestamp, TSVal, TSReply} | Acc]);
%% Alternate Checksum Request
decode_options(<<14, 3, Algo, Rest/binary>>, Acc) ->
    decode_options(Rest, [{alternate_csum_request, Algo} | Acc]);
%% Alternate Checksum
decode_options(<<15, Len, Tail/binary>>, Acc) ->
    CsumLen = Len - 2,
    <<CsumData:CsumLen/binary, Rest/binary>> = Tail,
    decode_options(Rest, [{alternate_csum, CsumData} | Acc]).

check_sum(16#FFFF, _IPH, _Length, _Data) ->
    no_checksum;
check_sum(Csum, #ipv4_pseudo_hdr{src=Src, dst=Dst, proto=Proto},
          Length, Data)
  when is_integer(Csum), is_binary(Data), is_integer(Length),
       is_binary(Src), is_binary(Dst), is_integer(Proto) ->
    Pkt = <<Src:4/binary, Dst:4/binary, 0:8, Proto:8/big,
           Length:16/big, Data/binary>>,
    enet_checksum:oc16_check(Pkt, Csum).
