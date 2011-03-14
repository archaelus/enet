%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc IPv4 Codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_ipv4).

%% API
-export([decode_addr/1, encode_addr/1
         ,decode/2
         ,encode/1, expand/1
         ,decode_protocol/1, encode_protocol/1
         ,header_checksum/1
         ,addr_len/0
        ]).

-include("enet_types.hrl").
-define(IP_VERSION, 4).
-define(IP_MIN_HDR_LEN, 5).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% API
%%====================================================================
decode(Dgram = <<?IP_VERSION:4, HLen:4, DiffServ:8, TotLen:16,
                ID:16, Flgs:3/bits, FragOff:13, TTL:8, Proto:8, HdrChkSum:16,
                SrcIP:4/binary, DestIP:4/binary, RestDgram/binary>>,
      DecodeOptions)
  when HLen >= 5, 4*HLen =< byte_size(Dgram) ->
    OptsLen = 4 * (HLen - ?IP_MIN_HDR_LEN),
    <<Opts:OptsLen/binary, Data/binary>> = RestDgram,
    Protocol = decode_protocol(Proto),
    IPH = #ip_pseudo_hdr{src=SrcIP, dst=DestIP, proto=Proto},
    #ipv4{vsn=?IP_VERSION,
          hlen=HLen,
          diffserv=DiffServ,
          totlen=TotLen,
          id=ID,
          flags=decode_flags(Flgs),
          frag_offset=FragOff,
          ttl=TTL,
          proto=Protocol,
          hdr_csum=check_header_checksum(Dgram, HLen, HdrChkSum),
          src=decode_addr(SrcIP),
          dst=decode_addr(DestIP),
          options=decode_options(Opts),
          data=enet_codec:decode(Protocol, Data,
                                 [ IPH | DecodeOptions ])};
decode(_Dgram, _) ->
    {error, bad_packet}.

expand(Pkt = #ipv4{options=Opts}) when is_list(Opts) ->
    expand(Pkt#ipv4{options=encode_options(Opts)});
expand(Pkt = #ipv4{hlen=H, options=Opts}) when not is_integer(H), is_binary(Opts) ->
    expand(Pkt#ipv4{hlen=?IP_MIN_HDR_LEN + (byte_size(Opts) div 4)});
expand(Pkt = #ipv4{flags=Flags}) when is_list(Flags) ->
    expand(Pkt#ipv4{flags=encode_flags(Flags)});
expand(Pkt = #ipv4{src=Src}) when not (is_binary(Src) andalso byte_size(Src) =:= 4) ->
    expand(Pkt#ipv4{src=encode_addr(Src)});
expand(Pkt = #ipv4{dst=Dst}) when not (is_binary(Dst) andalso byte_size(Dst) =:= 4) ->
    expand(Pkt#ipv4{dst=encode_addr(Dst)});
expand(Pkt = #ipv4{proto=P, data=D,
                   src=Src, dst=Dst})
  when not is_binary(D), is_atom(P), is_binary(Src),
       is_binary(Dst) ->
    Proto = encode_protocol(P),
    PsuedoHdr = #ip_pseudo_hdr{src=Src,dst=Dst,proto=Proto},
    expand(Pkt#ipv4{data=enet_codec:encode(P, D, PsuedoHdr)});
expand(Pkt = #ipv4{proto=P}) when not is_integer(P) ->
    expand(Pkt#ipv4{proto=encode_protocol(P)});
expand(Pkt = #ipv4{totlen=T, hlen=H, data=D})
  when not is_integer(T), is_integer(H), is_binary(D) ->
    expand(Pkt#ipv4{totlen=(H*4) + byte_size(D)});
expand(Pkt = #ipv4{hdr_csum=S}) when not is_integer(S) ->
    expand(Pkt#ipv4{hdr_csum=header_checksum(Pkt)});
expand(Pkt = #ipv4{vsn=?IP_VERSION,
                   hlen=HLen,
                   diffserv=DiffServ,
                   totlen=TotLen,
                   id=ID,
                   flags=Flags,
                   frag_offset=FragOff,
                   ttl=TTL,
                   proto=Proto,
                   hdr_csum=HdrChkSum,
                   src=SrcIP,
                   dst=DestIP,
                   options=Options,
                   data=Data})
  when is_integer(HLen), is_integer(DiffServ),
       is_integer(TotLen), is_integer(ID),
       is_bitstring(Flags), is_integer(FragOff), is_integer(TTL),
       is_integer(Proto),
       is_integer(HdrChkSum), is_binary(SrcIP), is_binary(DestIP),
       is_binary(Data), is_binary(Options) ->
    Pkt.

encode(#ipv4{vsn=?IP_VERSION,
             hlen=HLen,
             diffserv=DiffServ,
             totlen=TotLen,
             id=ID,
             flags=Flags,
             frag_offset=FragOff,
             ttl=TTL,
             proto=Proto,
             hdr_csum=HdrChkSum,
             src=SrcIP,
             dst=DestIP,
             options=Options,
             data=Data})
  when is_integer(HLen), is_integer(DiffServ),
       is_integer(TotLen), is_integer(ID),
       is_bitstring(Flags), is_integer(FragOff), is_integer(TTL),
       is_integer(Proto),
       is_integer(HdrChkSum), is_binary(SrcIP), is_binary(DestIP),
       is_binary(Data), is_binary(Options) ->
    OptsLen = byte_size(Options),
    RestDgram = <<Options:OptsLen/binary, Data/binary>>,
    <<?IP_VERSION:4, HLen:4, DiffServ:8, TotLen:16,
     ID:16, Flags:3/bits, FragOff:13, TTL:8, Proto:8, HdrChkSum:16,
     SrcIP:4/binary, DestIP:4/binary, RestDgram/binary>>;
encode(Pkt) ->
    encode(expand(Pkt)).

addr_len() -> 4.

decode_addr(B) when is_binary(B) ->
    string:join([ erlang:integer_to_list(N) || <<N:8>> <= B], ".").

encode_addr(A) when is_binary(A), byte_size(A) =:= 6 -> A;
encode_addr(L) when is_list(L) ->
    << << (erlang:list_to_integer(Oct)):8 >>
       || Oct <- string:tokens(L, ".") >>.

decode_flags(<<Evil:1, DF:1, MF:1>>) ->
    lists:foldl(fun ({Flag, 1}, Acc) -> [Flag | Acc];
                    (_, Acc) -> Acc
                end,
                [],
                [{dont_fragment, DF}, {more_fragments, MF},
                 {evil, Evil}]).

encode_flags(Flags) ->
    DF = case lists:member(dont_fragment, Flags) of true -> 1; false -> 0 end,
    MF = case lists:member(more_fragments, Flags) of true -> 1; false -> 0 end,
    Evil = case lists:member(evil, Flags) of true -> 1; false -> 0 end,
    <<Evil:1, DF:1, MF:1>>.

decode_options(Blob) ->
    decode_options(Blob, []).

decode_options(<<>>, Acc) ->
    lists:reverse(Acc);
decode_options(<<Copy:1, Class:2, Number:5, Data/binary>>, Acc) ->
    decode_option(Copy, {Class, Number}, Data, Acc).

decode_option(Copy, {0, 0}, _Data, Acc) ->
    lists:reverse([#ipv4_opt{type=eol, copy=Copy} | Acc]);
decode_option(Copy, {0, 1}, Data, Acc) ->
    decode_options(Data, [#ipv4_opt{type=nop, copy=Copy} | Acc]);
decode_option(Copy, {Class, Number}, <<Len:8/big, OptData/binary>>, Acc) ->
    DataLen = Len-2,
    <<Data:DataLen/binary, Rest/binary>> = OptData,
    decode_options(Rest, [#ipv4_opt{type=decode_option_type(Class, Number),
                                    copy=Copy, data=Data} | Acc]).

%% {ipv4_opt,rtralt,1,<<0,0>>}
encode_options(Options) ->
    iolist_to_binary([encode_option(Opt)
                      || Opt <- Options]).

encode_option(#ipv4_opt{type=Type,copy=Copy,data=Data}) ->
    {Class, Number} = encode_option_type(Type),
    OptSz = byte_size(Data) + 2,
    <<Copy:1, Class:2, Number:5, OptSz:8/big, Data/binary>>.

options_coding_test() ->
    OptList = [{ipv4_opt,rtralt,1,<<0,0>>}],
    ?assert( decode_options(encode_options(OptList)) =:= OptList ).


check_header_checksum(Dgram,HLen,HdrChkSum) when is_binary(Dgram),
                                                 is_integer(HLen),
                                                 is_integer(HdrChkSum) ->
    HeaderLen = 4 * HLen,
    <<Header:HeaderLen/binary, _/binary>> = Dgram,
    enet_checksum:oc16_check(Header, HdrChkSum).

header_checksum(#ipv4{vsn=?IP_VERSION,
                      hlen=HLen,
                      diffserv=DiffServ,
                      totlen=TotLen,
                      id=ID,
                      flags=Flags,
                      frag_offset=FragOff,
                      ttl=TTL,
                      proto=Proto,
                      hdr_csum=_,
                      src=SrcIP,
                      dst=DestIP,
                      options=Options})
  when is_integer(HLen), is_integer(DiffServ),
       is_integer(TotLen), is_integer(ID),
       is_bitstring(Flags), is_integer(FragOff), is_integer(TTL),
       is_binary(SrcIP), is_binary(DestIP),
       is_binary(Options) ->
    RestDgram = Options,
    Header = <<?IP_VERSION:4, HLen:4, DiffServ:8, TotLen:16,
              ID:16, Flags:3/bits, FragOff:13, TTL:8, Proto:8, 0:16,
              SrcIP:4/binary, DestIP:4/binary, RestDgram/binary>>,
    enet_checksum:oc16_sum(Header).

decode_option_type(0,  0) -> eool;
decode_option_type(0,  1) -> nop;
decode_option_type(0,  2) -> sec;
decode_option_type(0,  3) -> lsr;
decode_option_type(2,  4) -> ts;
decode_option_type(0,  5) -> 'e-sec';
decode_option_type(0,  6) -> cipso;
decode_option_type(0,  7) -> rr;
decode_option_type(0,  8) -> sid;
decode_option_type(0,  9) -> ssr;
decode_option_type(0, 10) -> zsu;
decode_option_type(0, 11) -> mtup;
decode_option_type(0, 12) -> mtur;
decode_option_type(2, 13) -> finn;
decode_option_type(0, 14) -> visa;
decode_option_type(0, 15) -> encode;
decode_option_type(0, 16) -> imitd;
decode_option_type(0, 17) -> eip;
decode_option_type(2, 18) -> tr;
decode_option_type(0, 19) -> addext;
decode_option_type(0, 20) -> rtralt;
decode_option_type(0, 21) -> sdb;
decode_option_type(0, 23) -> dps;
decode_option_type(0, 24) -> ump;
decode_option_type(0, 25) -> qs;
decode_option_type(0, 30) -> exp;
decode_option_type(2, 30) -> exp.

encode_option_type(eool) -> {0,  0};
encode_option_type(nop) -> {0,  1};
encode_option_type(sec) -> {0,  2};
encode_option_type(lsr) -> {0,  3};
encode_option_type(ts) -> {2,  4};
encode_option_type('e-sec') -> {0,  5};
encode_option_type(cipso) -> {0,  6};
encode_option_type(rr) -> {0,  7};
encode_option_type(sid) -> {0,  8};
encode_option_type(ssr) -> {0,  9};
encode_option_type(zsu) -> {0, 10};
encode_option_type(mtup) -> {0, 11};
encode_option_type(mtur) -> {0, 12};
encode_option_type(finn) -> {2, 13};
encode_option_type(visa) -> {0, 14};
encode_option_type(encode) -> {0, 15};
encode_option_type(imitd) -> {0, 16};
encode_option_type(eip) -> {0, 17};
encode_option_type(tr) -> {2, 18};
encode_option_type(addext) -> {0, 19};
encode_option_type(rtralt) -> {0, 20};
encode_option_type(sdb) -> {0, 21};
encode_option_type(dps) -> {0, 23};
encode_option_type(ump) -> {0, 24};
encode_option_type(qs) -> {0, 25};
encode_option_type(exp) -> {0, 30}.
%encode_option_type(exp) -> {2, 30}.

decode_protocol(0)   -> ip;
decode_protocol(1)   -> icmp;
decode_protocol(2)   -> igmp;
decode_protocol(3)   -> ggp;
decode_protocol(4)   -> ipencap;
decode_protocol(5)   -> st2;
decode_protocol(6)   -> tcp;
decode_protocol(7)   -> cbt;
decode_protocol(8)   -> egp;
decode_protocol(9)   -> igp;
decode_protocol(10)  -> 'bbn-rcc';
decode_protocol(11)  -> nvp;
decode_protocol(12)  -> pup;
decode_protocol(13)  -> argus;
decode_protocol(14)  -> emcon;
decode_protocol(15)  -> xnet;
decode_protocol(16)  -> chaos;
decode_protocol(17)  -> udp;
decode_protocol(18)  -> mux;
decode_protocol(19)  -> dcn;
decode_protocol(20)  -> hmp;
decode_protocol(21)  -> prm;
decode_protocol(22)  -> 'xns-idp';
decode_protocol(23)  -> 'trunk-1';
decode_protocol(24)  -> 'trunk-2';
decode_protocol(25)  -> 'leaf-1';
decode_protocol(26)  -> 'leaf-2';
decode_protocol(27)  -> rdp;
decode_protocol(28)  -> irtp;
decode_protocol(29)  -> 'iso-tp4';
decode_protocol(30)  -> netblt;
decode_protocol(31)  -> 'mfe-nsp';
decode_protocol(32)  -> 'merit-inp';
decode_protocol(33)  -> sep;
decode_protocol(34)  -> '3pc';
decode_protocol(35)  -> idpr;
decode_protocol(36)  -> xtp;
decode_protocol(37)  -> ddp;
decode_protocol(38)  -> 'idpr-cmtp';
decode_protocol(39)  -> 'tp++';
decode_protocol(40)  -> il;
decode_protocol(41)  -> ipv6;
decode_protocol(42)  -> sdrp;
decode_protocol(43)  -> ipv6_route;
decode_protocol(44)  -> ipv6_frag;
decode_protocol(45)  -> idrp;
decode_protocol(46)  -> rsvp;
decode_protocol(47)  -> gre;
decode_protocol(48)  -> mhrp;
decode_protocol(49)  -> bna;
decode_protocol(50)  -> esp;
decode_protocol(51)  -> ah;
decode_protocol(52)  -> 'i-nlsp';
decode_protocol(53)  -> swipe;
decode_protocol(54)  -> narp;
decode_protocol(55)  -> mobile;
decode_protocol(56)  -> tlsp;
decode_protocol(57)  -> skip;
decode_protocol(58)  -> icmp6;
decode_protocol(59)  -> ipv6_no_next;
decode_protocol(60)  -> ipv6_opts;
decode_protocol(62)  -> cftp;
decode_protocol(64)  -> 'sat-expak';
decode_protocol(65)  -> kryptolan;
decode_protocol(66)  -> rvd;
decode_protocol(67)  -> ippc;
decode_protocol(69)  -> 'sat-mon';
decode_protocol(70)  -> visa;
decode_protocol(71)  -> ipcv;
decode_protocol(72)  -> cpnx;
decode_protocol(73)  -> cphb;
decode_protocol(74)  -> wsn;
decode_protocol(75)  -> pvp;
decode_protocol(76)  -> 'br-sat-mon';
decode_protocol(77)  -> 'sun-nd';
decode_protocol(78)  -> 'wb-mon';
decode_protocol(79)  -> 'wb-expak';
decode_protocol(80)  -> 'iso-ip';
decode_protocol(81)  -> vmtp;
decode_protocol(82)  -> 'secure-vmtp';
decode_protocol(83)  -> vines;
decode_protocol(84)  -> ttp;
decode_protocol(85)  -> 'nsfnet-igp';
decode_protocol(86)  -> dgp;
decode_protocol(87)  -> tcf;
decode_protocol(88)  -> eigrp;
decode_protocol(89)  -> ospf;
decode_protocol(90)  -> 'sprite-rpc';
decode_protocol(91)  -> larp;
decode_protocol(92)  -> mtp;
decode_protocol(93)  -> 'ax.25';
decode_protocol(94)  -> ipip;
decode_protocol(95)  -> micp;
decode_protocol(96)  -> 'scc-sp';
decode_protocol(97)  -> etherip;
decode_protocol(98)  -> encap;
decode_protocol(100) -> gmtp;
decode_protocol(101) -> ifmp;
decode_protocol(102) -> pnni;
decode_protocol(103) -> pim;
decode_protocol(104) -> aris;
decode_protocol(105) -> scps;
decode_protocol(106) -> qnx;
decode_protocol(107) -> 'a/n';
decode_protocol(108) -> ipcomp;
decode_protocol(109) -> snp;
decode_protocol(110) -> 'compaq-peer';
decode_protocol(111) -> 'ipx-in-ip';
decode_protocol(112) -> vrrp;
decode_protocol(113) -> pgm;
decode_protocol(115) -> l2tp;
decode_protocol(116) -> ddx;
decode_protocol(117) -> iatp;
decode_protocol(118) -> st;
decode_protocol(119) -> srp;
decode_protocol(120) -> uti;
decode_protocol(121) -> smp;
decode_protocol(122) -> sm;
decode_protocol(123) -> ptp;
decode_protocol(124) -> isis;
decode_protocol(125) -> fire;
decode_protocol(126) -> crtp;
decode_protocol(127) -> crdup;
decode_protocol(128) -> sscopmce;
decode_protocol(129) -> iplt;
decode_protocol(130) -> sps;
decode_protocol(131) -> pipe;
decode_protocol(132) -> sctp;
decode_protocol(133) -> fc;
decode_protocol(254) -> divert.

encode_protocol(ip)            -> 0;
encode_protocol(icmp)          -> 1;
encode_protocol(igmp)          -> 2;
encode_protocol(ggp)           -> 3;
encode_protocol(ipencap)       -> 4;
encode_protocol(st2)           -> 5;
encode_protocol(tcp)           -> 6;
encode_protocol(cbt)           -> 7;
encode_protocol(egp)           -> 8;
encode_protocol(igp)           -> 9;
encode_protocol('bbn-rcc')     -> 10;
encode_protocol(nvp)           -> 11;
encode_protocol(pup)           -> 12;
encode_protocol(argus)         -> 13;
encode_protocol(emcon)         -> 14;
encode_protocol(xnet)          -> 15;
encode_protocol(chaos)         -> 16;
encode_protocol(udp)           -> 17;
encode_protocol(mux)           -> 18;
encode_protocol(dcn)           -> 19;
encode_protocol(hmp)           -> 20;
encode_protocol(prm)           -> 21;
encode_protocol('xns-idp')     -> 22;
encode_protocol('trunk-1')     -> 23;
encode_protocol('trunk-2')     -> 24;
encode_protocol('leaf-1')      -> 25;
encode_protocol('leaf-2')      -> 26;
encode_protocol(rdp)           -> 27;
encode_protocol(irtp)          -> 28;
encode_protocol('iso-tp4')     -> 29;
encode_protocol(netblt)        -> 30;
encode_protocol('mfe-nsp')     -> 31;
encode_protocol('merit-inp')   -> 32;
encode_protocol(sep)           -> 33;
encode_protocol('3pc')         -> 34;
encode_protocol(idpr)          -> 35;
encode_protocol(xtp)           -> 36;
encode_protocol(ddp)           -> 37;
encode_protocol('idpr-cmtp')   -> 38;
encode_protocol('tp++')        -> 39;
encode_protocol(il)            -> 40;
encode_protocol(ipv6)          -> 41;
encode_protocol(sdrp)          -> 42;
encode_protocol(ipv6_route)    -> 43;
encode_protocol(ipv6_frag)     -> 44;
encode_protocol(idrp)          -> 45;
encode_protocol(rsvp)          -> 46;
encode_protocol(gre)           -> 47;
encode_protocol(mhrp)          -> 48;
encode_protocol(bna)           -> 49;
encode_protocol(esp)           -> 50;
encode_protocol(ah)            -> 51;
encode_protocol('i-nlsp')      -> 52;
encode_protocol(swipe)         -> 53;
encode_protocol(narp)          -> 54;
encode_protocol(mobile)        -> 55;
encode_protocol(tlsp)          -> 56;
encode_protocol(skip)          -> 57;
encode_protocol(icmp6)         -> 58;
encode_protocol(ipv6_no_next)  -> 59;
encode_protocol(ipv6_opts)   -> 60;
encode_protocol(cftp)          -> 62;
encode_protocol('sat-expak')   -> 64;
encode_protocol(kryptolan)     -> 65;
encode_protocol(rvd)           -> 66;
encode_protocol(ippc)          -> 67;
encode_protocol('sat-mon')     -> 69;
encode_protocol(visa)          -> 70;
encode_protocol(ipcv)          -> 71;
encode_protocol(cpnx)          -> 72;
encode_protocol(cphb)          -> 73;
encode_protocol(wsn)           -> 74;
encode_protocol(pvp)           -> 75;
encode_protocol('br-sat-mon')  -> 76;
encode_protocol('sun-nd')      -> 77;
encode_protocol('wb-mon')      -> 78;
encode_protocol('wb-expak')    -> 79;
encode_protocol('iso-ip')      -> 80;
encode_protocol(vmtp)          -> 81;
encode_protocol('secure-vmtp') -> 82;
encode_protocol(vines)         -> 83;
encode_protocol(ttp)           -> 84;
encode_protocol('nsfnet-igp')  -> 85;
encode_protocol(dgp)           -> 86;
encode_protocol(tcf)           -> 87;
encode_protocol(eigrp)         -> 88;
encode_protocol(ospf)          -> 89;
encode_protocol('sprite-rpc')  -> 90;
encode_protocol(larp)          -> 91;
encode_protocol(mtp)           -> 92;
encode_protocol('ax.25')       -> 93;
encode_protocol(ipip)          -> 94;
encode_protocol(micp)          -> 95;
encode_protocol('scc-sp')      -> 96;
encode_protocol(etherip)       -> 97;
encode_protocol(encap)         -> 98;
encode_protocol(gmtp)          -> 100;
encode_protocol(ifmp)          -> 101;
encode_protocol(pnni)          -> 102;
encode_protocol(pim)           -> 103;
encode_protocol(aris)          -> 104;
encode_protocol(scps)          -> 105;
encode_protocol(qnx)           -> 106;
encode_protocol('a/n')         -> 107;
encode_protocol(ipcomp)        -> 108;
encode_protocol(snp)           -> 109;
encode_protocol('compaq-peer') -> 110;
encode_protocol('ipx-in-ip')   -> 111;
encode_protocol(vrrp)          -> 112;
encode_protocol(pgm)           -> 113;
encode_protocol(l2tp)          -> 115;
encode_protocol(ddx)           -> 116;
encode_protocol(iatp)          -> 117;
encode_protocol(st)            -> 118;
encode_protocol(srp)           -> 119;
encode_protocol(uti)           -> 120;
encode_protocol(smp)           -> 121;
encode_protocol(sm)            -> 122;
encode_protocol(ptp)           -> 123;
encode_protocol(isis)          -> 124;
encode_protocol(fire)          -> 125;
encode_protocol(crtp)          -> 126;
encode_protocol(crdup)         -> 127;
encode_protocol(sscopmce)      -> 128;
encode_protocol(iplt)          -> 129;
encode_protocol(sps)           -> 130;
encode_protocol(pipe)          -> 131;
encode_protocol(sctp)          -> 132;
encode_protocol(fc)            -> 133;
encode_protocol(divert)        -> 254.

%%====================================================================
%% Internal functions
%%====================================================================
