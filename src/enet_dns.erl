%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Experimental replacement for inet_dns
%% @end
%%%-------------------------------------------------------------------
-module(enet_dns).

%% API
-export([decode/2]).

-include_lib("kernel/src/inet_dns.hrl").

%%====================================================================
%% API
%%====================================================================

decode(Msg = <<ID:16,
              QR:1,OPCODE:4,
              AA:1,TC:1,RD:1,RA:1,
              _Z:3,RCODE:4,
              QDCOUNT:16,ANCOUNT:16,
              NSCOUNT:16,ARCOUNT:16,
              Rest/binary>>, _DecodeOpts) ->
    Header = #dns_header{id=ID,
                qr=QR,
                opcode=OPCODE,
                aa=AA,tc=TC,
                rd=RD,ra=RA,
                rcode=RCODE},
    {Queries,AnsRest} = decode_queries(Msg, QDCOUNT, Rest),
    {Answers,AuthRest} = decode_answers(Msg, ANCOUNT, AnsRest),
    {Authorities,AddRest} = decode_authority(Msg, NSCOUNT, AuthRest),
    {Additionals,_} = decode_additional(Msg, ARCOUNT, AddRest),
    [Header,Queries,Answers,Authorities,Additionals].
    
%%====================================================================
%% Internal functions
%%====================================================================

%% Query

decode_queries(Msg, Count, Rest) ->
    decode_queries(Msg, Count, Rest, []).

decode_queries(_Msg, 0, Rest, Acc) -> {Acc,Rest};
decode_queries(Msg, Count, Rest, Acc) ->
    {Name, <<QTYPE:16,QCLASS:16,QRest/binary>>} = decode_name(Msg, Rest),
    Q = #dns_query{domain=Name,
                   type=decode_type(QTYPE),
                   class=decode_class(QCLASS)},
    decode_queries(Msg, Count-1, QRest, Acc ++ [Q]).

%% Answers

decode_answers(Msg, Count, Rest) ->
    decode_answers(Msg, Count, Rest, []).

decode_answers(_Msg, 0, Rest, Acc) -> {Acc,Rest};
decode_answers(Msg, Count, Rest, Acc) ->
    {Name, <<Type:16,Class:16,TTL:32,
            RDLen:16,RD:RDLen/binary,
            RRest/binary>>} = decode_name(Msg, Rest),
    RRType = decode_type(Type),
    R = #dns_rr{domain=Name,
                type=RRType,
                class=decode_class(Class),
                ttl=TTL,
                data=decode_data(Msg, RRType, RD)},
    decode_answers(Msg, Count-1, RRest, Acc ++ [R]).

%% Authority

decode_authority(Msg, Count, Rest) ->
    decode_answers(Msg, Count, Rest).

%% Additional

decode_additional(Msg, Count, Rest) ->
    decode_answers(Msg, Count, Rest).

%% Name

decode_name(Msg, Data) ->
    decode_name(Msg, Data, []).

decode_name(_Msg, <<0, Rest/binary>>, Acc) ->
    {lists:flatten(Acc), Rest};
decode_name(Msg, <<1:1,1:1,Ptr:14,Rest/binary>>, Acc) ->
    <<_Skip:Ptr/binary,Name/binary>> = Msg,
    {CompName, _} = decode_name(Msg, Name, Acc),
    {case Acc of [] -> CompName; _ -> lists:flatten([Acc, ".", CompName]) end,
     Rest};
decode_name(Msg, <<Len:8,Name:Len/binary,Rest/binary>>, Acc) ->
    StrName = binary_to_list(Name),
    decode_name(Msg, Rest, case Acc of [] -> StrName; _ -> [Acc, ".", StrName] end).

%% Data

decode_data(_Msg, ?S_TXT, Bin) ->
    decode_txt(Bin);
decode_data(Msg, ?S_PTR, Bin) ->
    {Name,<<>>} = decode_name(Msg, Bin),
    Name;
decode_data(Msg, ?S_SRV, <<Prio:16/big
                           ,Weight:16/big
                           ,Port:16/big
                           ,NameData/binary>>) ->
    {Name, <<>>} = decode_name(Msg, NameData),
    {srv, Prio, Weight, Port, Name};
decode_data(_MSG, _Type, Data) ->
    Data.

decode_txt(<<Len:8, String:Len/binary, Rest/binary>>) ->
    [ String | decode_txt(Rest) ];
decode_txt(<<>>) ->
    [].

%%
%% Resource types
%%
decode_type(Type) ->
    case Type of
	?T_A -> ?S_A;
	?T_NS -> ?S_NS;
	?T_MD -> ?S_MD;
	?T_MF -> ?S_MF;
	?T_CNAME -> ?S_CNAME;
	?T_SOA -> ?S_SOA;
	?T_MB  -> ?S_MB;
	?T_MG  -> ?S_MG;
	?T_MR  -> ?S_MR;
	?T_NULL -> ?S_NULL;
	?T_WKS  -> ?S_WKS;
	?T_PTR  -> ?S_PTR;
	?T_HINFO -> ?S_HINFO;
	?T_MINFO -> ?S_MINFO;
	?T_MX -> ?S_MX;
	?T_TXT -> ?S_TXT;
	?T_AAAA -> ?S_AAAA;
	?T_SRV -> ?S_SRV;
	%% non standard
	?T_UINFO -> ?S_UINFO;
	?T_UID -> ?S_UID;
	?T_GID -> ?S_GID;
	?T_UNSPEC -> ?S_UNSPEC;
	%% Query type values which do not appear in resource records
	?T_AXFR -> ?S_AXFR;
	?T_MAILB -> ?S_MAILB;
	?T_MAILA -> ?S_MAILA;
	?T_ANY  -> ?S_ANY;
	_ -> Type    %% raw unknown type
    end.

%%
%% Resource types
%%
encode_type(Type) ->
    case Type of
	?S_A -> ?T_A;
	?S_NS -> ?T_NS;
	?S_MD -> ?T_MD;
	?S_MF -> ?T_MF;
	?S_CNAME -> ?T_CNAME;
	?S_SOA -> ?T_SOA;
	?S_MB -> ?T_MB;
	?S_MG -> ?T_MG;
	?S_MR -> ?T_MR;
	?S_NULL -> ?T_NULL;
	?S_WKS -> ?T_WKS;
	?S_PTR -> ?T_PTR;
	?S_HINFO -> ?T_HINFO;
	?S_MINFO -> ?T_MINFO;
	?S_MX -> ?T_MX;
	?S_TXT -> ?T_TXT;
	?S_AAAA -> ?T_AAAA;
	?S_SRV -> ?T_SRV;
	%% non standard
	?S_UINFO -> ?T_UINFO;
	?S_UID -> ?T_UID;
	?S_GID -> ?T_GID;
	?S_UNSPEC -> ?T_UNSPEC;
	%% Query type values which do not appear in resource records
	?S_AXFR -> ?T_AXFR;
	?S_MAILB -> ?T_MAILB;
	?S_MAILA -> ?T_MAILA;
	?S_ANY -> ?T_ANY;
	Type when is_integer(Type) -> Type    %% raw unknown type
    end.

%%
%% Resource clases
%%

decode_class(Class) ->
    case Class of
	?C_IN -> in;
	?C_CHAOS ->  chaos;
	?C_HS -> hs;
	?C_ANY -> any;
	_ -> Class    %% raw unknown class
    end.


encode_class(Class) ->
    case Class of
	in -> ?C_IN;
	chaos -> ?C_CHAOS;
	hs -> ?C_HS;
	any -> ?C_ANY;
	Class when is_integer(Class) -> Class    %% raw unknown class
    end.

