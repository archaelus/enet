%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc
%% @end
%%%-------------------------------------------------------------------
-module(enet_bertrpc).

-include_lib("proper/include/proper.hrl").

%% API
-export([decode/1
         ,decode_bertrpc/1
         ,decode_term/1
         ,encode/1
         ,round_trip/1
         ,parse_message/1
        ]).

-type bert_term() :: atom() | number() | <<_:_ * 8>> |
                     maybe_improper_list(bert_term(), bert_term() | []) |
                     {bert_term()} | {bert_term(), bert_term()} |
                     {bert_term(), bert_term(), bert_term()} |
                     {bert_term(), bert_term(), bert_term(), bert_term()}.

%%====================================================================
%% API
%%====================================================================

-spec decode(Data::binary()) -> {'complete', bert_term(), Rest::binary()} |
                                {'partial', BytesNeeded::non_neg_integer()}.
decode(<<Length:32/big, Data:Length/binary, Tail/binary>>) ->
    {Term, Rest} = decode_bertrpc(Data),
    {complete, Term, <<Rest/binary, Tail/binary>>};
decode(<<Length:32/big, Partial/binary>>) ->
    {partial, (Length - byte_size(Partial)) + 4};
decode(Huh) when is_binary(Huh) ->
    {partial, 4 - byte_size(Huh)}.

decode_bertrpc(<<131,Data/binary>>) ->
    decode_term(Data).

decode_term(<<97, Int, Rest/binary>>) ->
    {Int, Rest};
decode_term(<<98, Int:32/signed-big, Rest/binary>>) ->
    {Int, Rest};
decode_term(<<99, Float:31/binary, Rest/binary>>) ->
    {list_to_float(binary_to_list(Float)), Rest};
decode_term(<<100, Len:16/big, Atom:Len/binary, Rest/binary>>) ->
    {try erlang:binary_to_existing_atom(Atom, latin1)
     catch error:badarg ->
             {atom, Atom}
     end,
     Rest};
decode_term(<<104, Arity, Data/binary>>) ->
    decode_tuple(Arity, Data);
decode_term(<<105, Arity:32/big, Data/binary>>) ->
    decode_tuple(Arity, Data);
decode_term(<<106, Rest/binary>>) ->
    {[], Rest};
decode_term(<<107, Length:16/big, String:Length/binary, Rest/binary>>) ->
    {binary_to_list(String), Rest};
decode_term(<<108, Length:32/big, Data/binary>>) ->
    decode_list(Length, Data);
decode_term(<<109, Length:32/big, Bin:Length/binary, Rest/binary>>) ->
    {Bin, Rest};
decode_term(<<110, N, Sign, Body:N/binary, Rest/binary>>) ->
    {erlang:binary_to_term(<<131,110,N,Sign,Body:N/binary>>),
     Rest};
decode_term(<<111, N:32/big, Sign, Body:N/binary, Rest/binary>>) ->
    {erlang:binary_to_term(<<131,111,N:32/big,Sign,Body:N/binary>>),
     Rest}.

decode_tuple(Arity, Data) ->
    decode_tuple(Arity, Data, []).

decode_tuple(0, Data, Acc) ->
    {list_to_tuple(lists:reverse(Acc)), Data};
decode_tuple(Arity, Data, Acc) ->
    {Term, Rest} = decode_term(Data),
    decode_tuple(Arity - 1, Rest, [Term | Acc]).

decode_list(Length, Data) ->
    decode_list(Length, Data, []).

decode_list(0, Data, Acc) ->
    {Term, Rest} = decode_term(Data),
    {lists:append(lists:reverse(Acc), Term), Rest};
decode_list(Length, Data, Acc) ->
    {Term, Rest} = decode_term(Data),
    decode_list(Length - 1, Rest, [Term | Acc]).

-spec encode(Term::bert_term()) -> binary().
encode(Term) ->
    Bin = erlang:term_to_binary(Term),
    <<(byte_size(Bin)):32/big, Bin/binary>>.

-spec round_trip(Term::bert_term()) -> true.
round_trip(Term) ->
    {complete, Term, <<>>} =:= decode(encode(Term)).


-type bert_message() :: {'call', M::atom(), F::atom(), A::list(bert_term())} |
                        {'cast', M::atom(), F::atom(), A::list(bert_term())} |
                        {'response', Reply::bert_term()} |
                        {'noreply'} |
                        {'error', Reason::bert_term()}.

-spec parse_message(Term::bert_message()) ->
                           {'request',
                            'call' | 'cast', Info::term()} |
                           {'response',
                            'call' | 'cast' | 'error', Info::term()} |
                           {'bad_message', Term::bert_term()}.
parse_message({call, M, F, A}) ->
    {request, call, [M, F, A]};
parse_message({reply, Reply}) ->
    {response, call, Reply};
parse_message({cast, M, F, A}) ->
    {request, cast, [M, F, A]};
parse_message({noreply}) ->
    {response, cast, undefined};
parse_message({error, Err}) ->
    {response, error, Err};
parse_message(Term) ->
    {bad_message, Term}.

%%====================================================================
%% Internal functions
%%====================================================================
