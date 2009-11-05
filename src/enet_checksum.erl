%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet checksum routines.
%% @end
%%%-------------------------------------------------------------------
-module(enet_checksum).

%% API
-export([oc16/1
         ,oc16_sum/1
         ,oc16_check/2
        ]).

%%====================================================================
%% API
%%====================================================================

%% 16bit Ones complement checksum of a given binary.
oc16(Bin) when is_binary(Bin) ->
    lists:foldl(fun oc16/2,
                0,
                [N || <<N:16>> <= Bin]).

%% Calculate the ones complement of the 16bit ones complement sum of
%% the input binary.
oc16_sum(Bin) ->
    (bnot oc16(Bin)) band 16#FFFF.

%% 16 bits Ones complement addition.
oc16(A, Sum) ->
    case A + Sum of
        N when N > 16#FFFF ->
            Carry = N bsr 16,
            (N band 16#FFFF) + Carry;
        N when N =< 16#FFFF ->
            N
    end.

oc16_check(Bin, Sum) ->
    case oc16(Bin) of
        16#FFFF -> correct; %% -0
        _ -> {incorrect, Sum}
    end.


%%====================================================================
%% Internal functions
%%====================================================================

oc_fmt(N) ->
    <<Sign:1, Num:15>> = <<N:16>>,
    case Sign of
        0 -> integer_to_list(Num);
        1 -> "-" ++ integer_to_list(Num)
    end.
