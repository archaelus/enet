%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc UDP Codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_udp).

%% API
-export([decode/1, decode/2, encode/1,
         decode_port/1, encode_port/1]).

-include("types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(Data) -> decode(Data, []).

decode(<<Src:16/big, Dst:16/big,
        Length:16/big, Csum:16/big,
        Data/binary>>, _DecodeOpts) when byte_size(Data) =:= Length - 8 ->
    case decode_port(Dst) of
        Dns when Dns =:= <<"dns">>; Dns =:= <<"mdns">> ->
            #udp{src_port=decode_port(Src), dst_port=decode_port(Dst),
                 length=Length, csum=Csum,
                 data=enet_dns:decode(Data)};
        _ ->
            #udp{src_port=decode_port(Src), dst_port=decode_port(Dst),
                 length=Length, csum=Csum,
                 data=Data}
    end;
decode(_Packet, _DecodeOpts) ->
    {error, bad_packet}.

encode(Pkt = #udp{src_port=Src}) when is_binary(Src) ->
    encode(Pkt#udp{src_port=encode_port(Src)});
encode(Pkt = #udp{dst_port=Dst}) when is_binary(Dst) ->
    encode(Pkt#udp{dst_port=encode_port(Dst)});
encode(#udp{src_port=Src, dst_port=Dst,
            data=Data}) ->
    Length = byte_size(Data),
    Csum = 0, % XXX - omitted
    <<Src:16/big, Dst:16/big,
        (Length + 8):16/big, Csum:16/big,
        Data:Length/binary>>.

decode_port(Port) ->
    enet_services:decode_port(udp, Port).

encode_port(Port) ->
    enet_services:encode_port(udp, Port).

%%====================================================================
%% Internal functions
%%====================================================================
