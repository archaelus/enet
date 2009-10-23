%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ARP packet codec
%% @end
%%%-------------------------------------------------------------------
-module(arp).

%% API
-export([decode/1,encode/1]).

-include("types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(<<HType:16/big, PType:16/big,
        HAddrLen/big, PAddrLen/big,
        Oper:16/big,
        SndrHAddr:HAddrLen/binary,
        SndrPAddr:PAddrLen/binary,
        TargHAddr:HAddrLen/binary,
        TargPAddr:PAddrLen/binary>>) ->
    H = decode_htype(HType), P = decode_ptype(PType),
    #arp{htype=H, ptype=P,
         haddrlen=HAddrLen, paddrlen=PAddrLen,
         op=decode_op(Oper),
         sender={(codec:module(H)):decode_addr(SndrHAddr),
                 (codec:module(P)):decode_addr(SndrPAddr)},
         target={(codec:module(H)):decode_addr(TargHAddr),
                 (codec:module(P)):decode_addr(TargPAddr)}}.

encode(P = #arp{htype=ethernet,
                haddrlen=undefined,
                sender={SndrHAddr, SndrPAddr},
                target={TargHAddr, TargPAddr}}) ->
    encode(P#arp{htype=ethernet,
                 haddrlen=(codec:module(ethernet)):addr_len(),
                 sender={(codec:module(ethernet)):encode_addr(SndrHAddr), SndrPAddr},
                 target={(codec:module(ethernet)):encode_addr(TargHAddr), TargPAddr}});
encode(P = #arp{ptype=ipv4,
                paddrlen=undefined,
                sender={SndrHAddr, SndrPAddr},
                target={TargHAddr, TargPAddr}}) ->
    encode(P#arp{ptype=ipv4,
                 paddrlen=(codec:module(ipv4)):addr_len(),
                 sender={SndrHAddr, (codec:module(ipv4)):encode_addr(SndrPAddr)},
                 target={TargHAddr, (codec:module(ipv4)):encode_addr(TargPAddr)}});

encode(#arp{htype=HType, ptype=PType,
            haddrlen=HAddrLen, paddrlen=PAddrLen,
            op=Oper,
            sender={SndrHAddr, SndrPAddr},
            target={TargHAddr, TargPAddr}})
  when byte_size(SndrHAddr) =:= byte_size(TargHAddr),
       byte_size(SndrHAddr) =:= HAddrLen,
       byte_size(SndrPAddr) =:= byte_size(TargPAddr),
       byte_size(SndrPAddr) =:= PAddrLen ->
    <<(encode_htype(HType)):16/big,
     (encode_ptype(PType)):16/big,
     HAddrLen/big, PAddrLen/big,
     (encode_op(Oper)):16/big,
     SndrHAddr:HAddrLen/binary,
     SndrPAddr:PAddrLen/binary,
     TargHAddr:HAddrLen/binary,
     TargPAddr:PAddrLen/binary>>.

%%====================================================================
%% Internal functions
%%====================================================================

decode_op(1) -> request;
decode_op(2) -> reply.

encode_op(request) -> 1;
encode_op(reply) -> 2.

decode_htype(1) -> ethernet.
encode_htype(ethernet) -> 1.

decode_ptype(P) -> eth:decode_type(P).
encode_ptype(P) -> eth:encode_type(P).
    
