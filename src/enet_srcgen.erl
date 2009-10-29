%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Generate parts of the enet source code
%% @end
%%%-------------------------------------------------------------------
-module(enet_srcgen).

%% API
-export([write_file/1]).

%%====================================================================
%% API
%%====================================================================

write_file(File) ->
    Services = services(),
    file:write_file(File, iolist_to_binary([funs(Services)])).

services() ->
    {ok, Services} = inet_parse:services("/etc/services"),
    Services.

funs(Services) ->
    UdpProtoList = lists:ukeysort(3, lists:ukeysort(2, [{Trans, Proto, Number} || {Proto, Trans = udp, Number, _} <- Services])),
    TcpProtoList = lists:ukeysort(3, lists:ukeysort(2, [{Trans, Proto, Number} || {Proto, Trans = tcp, Number, _} <- Services])),
    ProtoList = UdpProtoList ++ TcpProtoList,
    erl_prettypr:format(erl_syntax:form_list([erl_syntax:function(erl_syntax:atom(decode_port),
                                            [erl_syntax:clause([erl_syntax:atom(Trans), erl_syntax:integer(Port)], none,
                                                               [{bin,1,
                                                                 [{bin_element,1,{string,1,case Protocol of Atom when is_atom(Atom) -> atom_to_list(Atom); _ -> Protocol end},default,default}]}]) 
                                             || {Trans, Protocol, Port} <- ProtoList]),
                        erl_syntax:function(erl_syntax:atom(encode_port),
                                            [erl_syntax:clause([erl_syntax:atom(Trans),
                                                                {bin,1,
                                                                 [{bin_element,1,{string,1,case Protocol of Atom when is_atom(Atom) -> atom_to_list(Atom); _ -> Protocol end},default,default}]}], none,
                                                               [erl_syntax:integer(Port)]) 
                                             || {Trans, Protocol, Port} <- ProtoList])])).


%%====================================================================
%% Internal functions
%%====================================================================
