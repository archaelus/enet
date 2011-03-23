%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc UDP Codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_udp).

%% API
-export([decode/2
         ,expand/2
         ,encode/2
         ,decode_port/1
         ,encode_port/1
        ]).

-include("enet_types.hrl").
-define(UDP_HEADER_LEN, 8).

%%====================================================================
%% API
%%====================================================================

decode(<<Src:16/big, Dst:16/big,
        Length:16/big, Csum:16/big,
        Data/binary>> = Pkt,
       [IPH = #ip_pseudo_hdr{} | DecodeOpts])
  when byte_size(Data) =:= Length - ?UDP_HEADER_LEN ->
    Udp = #udp{src_port=decode_port(Src),
               dst_port=decode_port(Dst),
               length=Length,
               csum=check_sum(Csum, IPH, Length, Pkt)},
    case Udp#udp.dst_port of
        Dns when Dns =:= <<"dns">>; Dns =:= <<"mdns">> ->
            Udp#udp{data=enet_dns:decode(Data, DecodeOpts)};
        _ ->
            Udp#udp{data=Data}
    end;
decode(_Packet, _DecodeOpts) ->
    {error, bad_packet}.

expand(#udp{data=Data}, _) when not is_binary(Data) ->
    erlang:error({udp_payload_not_encoded, Data});

expand(Pkt = #udp{length=undefined,
                  data=Data}, O) when is_binary(Data) ->
    expand(Pkt#udp{length=(byte_size(Data) + ?UDP_HEADER_LEN)}, O);
expand(Pkt = #udp{src_port=Src}, O) when not is_binary(Src);
                                         is_binary(Src), byte_size(Src) =/= 2 ->
    Port = encode_port(Src),
    expand(Pkt#udp{src_port= <<Port:16/big>>}, O);
expand(Pkt = #udp{dst_port=Dst}, O) when not is_binary(Dst);
                                         is_binary(Dst), byte_size(Dst) =/= 2 ->
    Port = encode_port(Dst),
    expand(Pkt#udp{dst_port= <<Port:16/big>>}, O);
expand(Pkt = #udp{src_port=Src,
                  dst_port=Dst,
                  length=Length,
                  csum=Csum,
                  data=Data}, O)
  when is_binary(Src), is_binary(Dst),
       is_integer(Length), not is_integer(Csum),
       is_binary(Data) ->
    DataLength=Length - ?UDP_HEADER_LEN,
    PseudoPkt = <<Src:2/binary, Dst:2/binary,
                 Length:16/big, 0:16/big,
                 Data:DataLength/binary>>,
    Sum = sum(PseudoPkt, Length, O),
    expand(Pkt#udp{csum=Sum}, O);
expand(Pkt = #udp{src_port=Src,
                  dst_port=Dst,
                  length=Length,
                  csum=Csum,
                  data=Data}, _)
  when is_binary(Src), is_binary(Dst),
       is_integer(Length), is_integer(Csum),
       is_binary(Data) ->
    Pkt.

encode(#udp{src_port=Src,
            dst_port=Dst,
            length=Length,
            csum=Csum,
            data=Data}, _)
  when is_binary(Src), is_binary(Dst),
       is_integer(Length), is_integer(Csum),
       is_binary(Data) ->
    DataLength=Length - ?UDP_HEADER_LEN,
    <<Src:2/binary, Dst:2/binary,
     Length:16/big, Csum:16/big,
     Data:DataLength/binary>>;
encode(Pkt, O) ->
    encode(expand(Pkt, O), O).

decode_port(Port) ->
    enet_services:decode_port(udp, Port).

encode_port(Port) ->
    enet_services:encode_port(udp, Port).

check_sum(16#FFFF, _IPH, _Length, _Data) ->
    no_checksum;
check_sum(Csum, #ip_pseudo_hdr{src=Src, dst=Dst, proto=Proto},
          Length, Data)
  when is_integer(Csum), is_binary(Data), is_integer(Length),
       is_binary(Src), is_binary(Dst), is_integer(Proto),
       byte_size(Src) =:= byte_size(Dst),
       byte_size(Src) =:= 4 ->
    Pkt = <<Src:4/binary, Dst:4/binary, 0:8, Proto:8/big, Length:16/big,
           Data/binary>>,
    enet_checksum:oc16_check(Pkt, Csum);
check_sum(Csum, #ip_pseudo_hdr{src=Src, dst=Dst, proto=Proto},
          Length, Data)
  when is_integer(Csum), is_binary(Data), is_integer(Length),
       is_binary(Src), is_binary(Dst), is_integer(Proto),
       byte_size(Src) =:= byte_size(Dst),
       byte_size(Src) =:= 16 ->
    Pkt = <<Src:16/binary, Dst:16/binary, Length:16/big,
            0:24, Proto:8/big, Data/binary>>,
    enet_checksum:oc16_check(Pkt, Csum).

sum(Data, Length, #ip_pseudo_hdr{src=Src, dst=Dst, proto=Proto})
  when byte_size(Src) =:= byte_size(Dst),
       byte_size(Src) =:= 4 ->
    Pkt = <<Src:4/binary, Dst:4/binary, 0:8, Proto:8/big, Length:16/big,
           Data/binary>>,
    enet_checksum:oc16_sum(Pkt);
sum(Data, Length, [#ip_pseudo_hdr{src=Src, dst=Dst, proto=Proto}|_])
  when byte_size(Src) =:= byte_size(Dst),
       byte_size(Src) =:= 16 ->
    Pkt = <<Src:16/binary, Dst:16/binary, Length:16/big,
            0:24, Proto:8/big, Data/binary>>,
    enet_checksum:oc16_sum(Pkt).



%%====================================================================
%% Internal functions
%%====================================================================
