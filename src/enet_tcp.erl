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
         ,encode/2
         ,decode_port/1
         ,encode_port/1]).

-include_lib("eunit/include/eunit.hrl").

-include("enet_types.hrl").
-define(TCP_HEADER_MIN_LEN, 20).
-define(TCP_OPTS_ALIGNMENT, 4).

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
       [IPH = #ipv4_pseudo_hdr{} | _DecodeOpts]) ->
    HeaderLen = ?TCP_OPTS_ALIGNMENT*DataOffset,
    OptsLen = HeaderLen - ?TCP_HEADER_MIN_LEN,
    <<Options:OptsLen/binary,
      TcpData/binary>> = Data,
    #tcp{src_port=decode_port(Src)
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

encode(#tcp{src_port=Src
            ,dst_port=Dst
            ,seq_no=SeqNo
            ,ack_no=AckNo
            ,data_offset=DataOffset
            ,reserved=Reserved
            ,urg=Urg, ack=Ack, psh=Psh
            ,rst=Rst, syn=Syn, fin=Fin
            ,window=Window
            ,csum=Csum
            ,urg_pointer=UrgPointer
            ,options=Options
            ,data=TcpData
           }, _)
  when is_binary(Src), is_binary(Dst),
       is_integer(SeqNo),
       is_integer(AckNo),
       is_integer(DataOffset),
       is_integer(Reserved),
       is_integer(Urg), is_integer(Ack), is_integer(Psh),
       is_integer(Rst), is_integer(Syn), is_integer(Fin),
       is_integer(Window),
       is_integer(Csum),
       is_integer(UrgPointer),
       is_binary(Options),
       is_binary(TcpData) ->
    OptSize = byte_size(Options),
    PadLen = ?TCP_OPTS_ALIGNMENT - ((?TCP_HEADER_MIN_LEN + OptSize) rem ?TCP_OPTS_ALIGNMENT),
    Padding = case PadLen of
                  0 -> <<>>;
                  _N -> <<0:(PadLen*8)>>
              end,
    MyDataOffset = (?TCP_HEADER_MIN_LEN + OptSize + PadLen) div ?TCP_OPTS_ALIGNMENT,
    DataOffset = MyDataOffset,
    <<Src:2/binary, Dst:2/binary,
      SeqNo:32/big, AckNo:32/big,
      DataOffset:4, Reserved:6,
      Urg:1, Ack:1, Psh:1, Rst:1, Syn:1, Fin:1,
      Window:16/big,
      Csum:16/big, UrgPointer:16/big,
      Options/binary,
      Padding/binary,
      TcpData/binary>>;
encode(TcpPacket = #tcp{}, EncodeOptions) ->
    encode(expand(TcpPacket, EncodeOptions), EncodeOptions).

expand(#tcp{data=Data}, _) when not is_binary(Data) ->
    erlang:error({tcp_payload_not_encoded, Data});
expand(Pkt = #tcp{src_port=Src}, O) when not is_binary(Src);
                                         is_binary(Src), byte_size(Src) =/= 2 ->
    Port = encode_port(Src),
    expand(Pkt#tcp{src_port= <<Port:16/big>>}, O);
expand(Pkt = #tcp{dst_port=Dst}, O) when not is_binary(Dst);
                                         is_binary(Dst), byte_size(Dst) =/= 2 ->
    Port = encode_port(Dst),
    expand(Pkt#tcp{dst_port= <<Port:16/big>>}, O);

expand(Pkt = #tcp{options=OptList}, O) when is_list(OptList) ->
    EncodedOptions = encode_options(OptList),
    expand(Pkt#tcp{options=EncodedOptions}, O);

expand(Pkt = #tcp{urg=Flag}, O) when is_atom(Flag) ->
    expand(Pkt#tcp{urg=encode_flag(Flag)}, O);
expand(Pkt = #tcp{ack=Flag}, O) when is_atom(Flag) ->
    expand(Pkt#tcp{ack=encode_flag(Flag)}, O);
expand(Pkt = #tcp{psh=Flag}, O) when is_atom(Flag) ->
    expand(Pkt#tcp{psh=encode_flag(Flag)}, O);
expand(Pkt = #tcp{rst=Flag}, O) when is_atom(Flag) ->
    expand(Pkt#tcp{rst=encode_flag(Flag)}, O);
expand(Pkt = #tcp{syn=Flag}, O) when is_atom(Flag) ->
    expand(Pkt#tcp{syn=encode_flag(Flag)}, O);
expand(Pkt = #tcp{fin=Flag}, O) when is_atom(Flag) ->
    expand(Pkt#tcp{fin=encode_flag(Flag)}, O);

expand(Pkt = #tcp{csum={incorrect, Value}}, O) ->
    expand(Pkt#tcp{csum=Value}, O);

expand(#tcp{src_port=Src
            ,dst_port=Dst
            ,seq_no=SeqNo
            ,ack_no=AckNo
            ,data_offset=DataOffset
            ,reserved=Reserved
            ,urg=Urg, ack=Ack, psh=Psh
            ,rst=Rst, syn=Syn, fin=Fin
            ,window=Window
            ,csum=correct
            ,urg_pointer=UrgPointer
            ,options=Options
            ,data=TcpData
           } = Pkt, O)
  when is_binary(Src), is_binary(Dst),
       is_integer(SeqNo),
       is_integer(AckNo),
       is_integer(DataOffset),
       is_integer(Reserved),
       is_integer(Urg), is_integer(Ack), is_integer(Psh),
       is_integer(Rst), is_integer(Syn), is_integer(Fin),
       is_integer(Window),
       is_integer(UrgPointer),
       is_binary(Options),
       is_binary(TcpData) ->
    PseudoPkt = encode(Pkt#tcp{csum=0}, O),
    NewCsum = sum(PseudoPkt, byte_size(PseudoPkt), O),
    expand(Pkt#tcp{csum=NewCsum}, O);

expand(#tcp{src_port=Src
            ,dst_port=Dst
            ,seq_no=SeqNo
            ,ack_no=AckNo
            ,data_offset=DataOffset
            ,reserved=Reserved
            ,urg=Urg, ack=Ack, psh=Psh
            ,rst=Rst, syn=Syn, fin=Fin
            ,window=Window
            ,csum=Csum
            ,urg_pointer=UrgPointer
            ,options=Options
            ,data=TcpData
           } = ExpandedPkt, _)
  when is_binary(Src), is_binary(Dst),
       is_integer(SeqNo),
       is_integer(AckNo),
       is_integer(DataOffset),
       is_integer(Reserved),
       is_integer(Urg), is_integer(Ack), is_integer(Psh),
       is_integer(Rst), is_integer(Syn), is_integer(Fin),
       is_integer(Window),
       is_integer(Csum),
       is_integer(UrgPointer),
       is_binary(Options),
       is_binary(TcpData) ->
    ExpandedPkt.

encode_port(Port) ->
    enet_services:encode_port(tcp, Port).

%%====================================================================
%% Internal functions
%%====================================================================

decode_flag(0) -> false;
decode_flag(1) -> true.

encode_flag(false) -> 0;
encode_flag(true) -> 1.

decode_options(Blob) ->
    decode_options(Blob, []).

decode_options(<<>>, Acc) ->
    lists:reverse(Acc);
%% End of Options List (padding?)
decode_options(<<0, Rest/binary>>, Acc) -> decode_options(Rest, Acc);
%% Nop
decode_options(<<1, Rest/binary>>, Acc) -> decode_options(Rest, [nop | Acc]);
%% MSS
decode_options(<<2, 4, MSS:16/big, Rest/binary>>, Acc) ->
    decode_options(Rest, [{mss, MSS} | Acc]);
%% Window Size Shift
decode_options(<<3, 3, Shift:8, Rest/binary>>, Acc) ->
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
    decode_options(Rest, [{alternate_csum, CsumData} | Acc]);
decode_options(<<OptionData/binary>>, Acc) ->
    [{error, {unknown_opt_data, OptionData}} | Acc].

encode_options(OptionList) ->
    iolist_to_binary([encode_option(Opt)
                      || Opt <- OptionList]).

encode_option(nop) ->
    <<1>>;
encode_option({mss, MSS}) ->
    <<2, 4, MSS:16/big>>;
encode_option({window_size_shift, Shift}) ->
    <<3, 3, Shift:8>>;
encode_option(sack_ok) ->
    <<4, 2>>;
encode_option({sack, SackData}) ->
    <<5, ( byte_size(SackData) + 2):8,
      SackData/binary>>;
encode_option({timestamp, TSVal, TSReply}) ->
    <<8, 10, TSVal:32, TSReply:32>>.


check_sum(16#FFFF, _IPH, _Length, _Data) ->
    no_checksum;
check_sum(Csum, #ipv4_pseudo_hdr{src=Src, dst=Dst, proto=Proto},
          Length, Data)
  when is_integer(Csum), is_binary(Data), is_integer(Length),
       is_binary(Src), is_binary(Dst), is_integer(Proto) ->
    Pkt = <<Src:4/binary, Dst:4/binary, 0:8, Proto:8/big,
           Length:16/big, Data/binary>>,
    enet_checksum:oc16_check(Pkt, Csum).

sum(Data, Length, [#ipv4_pseudo_hdr{src=Src, dst=Dst, proto=Proto}|_]) ->
    Pkt = <<Src:4/binary, Dst:4/binary, 0:8, Proto:8/big, Length:16/big,
            Data/binary>>,
    enet_checksum:oc16_sum(Pkt).


encode_pkt_test() ->
    ?assertMatch(B when is_binary(B),
                 encode(#tcp{src_port = 58903,dst_port = <<"http">>,
                             seq_no = 60622703,ack_no = 0,data_offset = 11,
                             reserved = 0,urg = false,ack = false,psh = false,
                             rst = false,syn = true,
                             fin = false,window = 65535,
                             csum = correct,urg_pointer = 0,
                             options = [{mss,1460},
                                        nop,
                                        {window_size_shift,3},
                                        nop,nop,
                                        {timestamp,311329929,0},
                                        sack_ok],
                             data = <<>>},
                        [{ipv4_pseudo_hdr,<<192,168,2,1>>,<<192,168,2,2>>,6}])).
