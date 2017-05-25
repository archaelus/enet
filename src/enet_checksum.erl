%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet checksum routines.
%% @end
%%%-------------------------------------------------------------------
-module(enet_checksum).
-compile(native).

%% API
-export([oc16/1
         ,oc16_sum/1
         ,oc16_check/2
        ]).

%%====================================================================
%% API
%%====================================================================

%% 16bit Ones complement checksum of a given binary.
oc16(Bin)
  when is_binary(Bin) ->
    oc16(Bin, 0).

oc16(<<A:16,B:16,Bin/binary>>,Sum) -> oc16(Bin, A+B+Sum);
oc16(<<A:16,B:8>>, Sum)  -> oc16_fold(A+(B bsl 8)+Sum);
oc16(<<A:16>>, Sum)  -> oc16_fold(A+Sum);
oc16(<<A:8>>, Sum) -> oc16_fold((A bsl 8)+Sum);
oc16(<<>>, Sum) -> oc16_fold(Sum).

%% Calculate the ones complement of the 16bit ones complement sum of
%% the input binary.
oc16_sum(Bin)
  when is_binary(Bin) ->
    (bnot oc16(Bin)) band 16#FFFF.

oc16_check(Bin, Sum)
  when is_binary(Bin) ->
    case oc16(Bin) of
        16#FFFF -> correct; %% -0
        _ -> {incorrect, Sum}
    end.

%% fold 16-bit carry
oc16_fold(Sum) when Sum > 16#ffff ->
    oc16_fold((Sum band 16#ffff) + (Sum bsr 16));
oc16_fold(Sum) ->
    Sum.
