%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc enet_codec eunit tests.
%% @end

-module(enet_codec_tests).

-include_lib("eunit/include/eunit.hrl").

udp_encode_test() ->
    WireData = <<255,255,255,255,255,255,110,203,203,23,242,100,8,
                 0,69,0,0,78,207,115,0,0,64,17,36,219,192,168,2,1,
                 192,168,2,255,205,9,0,137,0,58,186,242,71,37,1,16,
                 0,1,0,0,0,0,0,0,32,65,66,65,67,70,80,70,80,69,78,
                 70,68,69,67,70,67,69,80,70,72,70,68,69,70,70,80,
                 70,80,65,67,65,66,0,0,32,0,1>>,
    Packet = {eth,"6E:CB:CB:17:F2:64",broadcast,ipv4,
              {ipv4,4,5,0,78,53107,[],0,64,udp,correct,"192.168.2.1",
               "192.168.2.255",[],
               {udp,52489,<<"netbios-ns">>,58,correct,
                <<71,37,1,16,0,1,0,0,0,0,0,0,32,65,66,65,
                  67,70,80,70,80,69,78,70,68,69,67,70,67,
                  69,80,70,72,70,68,69,70,70,80,70,80,65,
                  67,65,66,0,0,32,0,1>>}}},
    ?assertMatch(ReEncoded when ReEncoded =:= WireData,
                 enet_codec:encode(eth, Packet)).
