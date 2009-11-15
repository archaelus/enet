%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc UDP Codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_udp).

%% API
-export([decode/2, encode/1,
         decode_port/1, encode_port/1]).

-include("types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(<<Src:16/big, Dst:16/big,
        Length:16/big, Csum:16/big,
        Data/binary>> = Pkt,
       [IPH = #ipv4_pseudo_hdr{} | _DecodeOpts])
  when byte_size(Data) =:= Length - 8 ->
    case decode_port(Dst) of
        Dns when Dns =:= <<"dns">>; Dns =:= <<"mdns">> ->
            #udp{src_port=decode_port(Src), dst_port=decode_port(Dst),
                 length=Length, csum=check_sum(Csum, IPH, Length, Data),
                 data=enet_dns:decode(Data)};
        _ ->
            #udp{src_port=decode_port(Src), dst_port=decode_port(Dst),
                 length=Length, csum=Csum,
                 data=Data}
    end;
decode(_Packet, _DecodeOpts) ->
    {error, bad_packet}.


expand(Pkt = #udp{length=undefined,
                  data=Data}) when is_binary(Data) ->
    encode(Pkt#udp{length=byte_size(Data)});
expand(Pkt = #udp{src_port=Src}) when not is_binary(Src) ->
    expand(Pkt#udp{src_port=encode_port(Src)});
expand(Pkt = #udp{dst_port=Dst}) when not is_binary(Dst) ->
    expand(Pkt#udp{dst_port=encode_port(Dst)});
expand(Pkt = #udp{src_port=Src,
                  dst_port=Dst,
                  length=Length,
                  csum=Csum,
                  data=Data})
  when is_binary(Src), is_binary(Dst),
       is_integer(Length), is_integer(Csum),
       is_binary(Data) ->
    Pkt.

encode(#udp{src_port=Src,
            dst_port=Dst,
            length=Length,
            csum=Csum,
            data=Data})
  when is_binary(Src), is_binary(Dst),
       is_integer(Length), is_integer(Csum),
       is_binary(Data) ->
    <<Src:16/big, Dst:16/big,
     (Length + 8):16/big, Csum:16/big,
     Data:Length/binary>>;
encode(Pkt) ->
    encode(expand(Pkt)).

decode_port(Port) ->
    enet_services:decode_port(udp, Port).

encode_port(Port) ->
    enet_services:encode_port(udp, Port).

check_sum(Csum, #ipv4_pseudo_hdr{src=Src, dst=Dst, proto=Proto},
          Length, Data) ->
    Pkt = <<Src:32, Dst:32, 0:8, Proto:8, Length:16,
           Data/binary>>,
    enet_checksum:oc16_sum(Pkt, Csum).

%%====================================================================
%% Internal functions
%%====================================================================
