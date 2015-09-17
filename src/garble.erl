-module(garble).

-export([en/2, de/2, delta_len/1]).

% [
% 	{insert, {Pos, Len}, random},	Done
% 	{insert, Pos, <<....>>},		Done
% 	{swap, Pos1, Pos2, Len},		Done
% 	{x_or, Pos, <<...>>}			TODO
% 	]

en(Data, []) -> Data;
en(Data, Script) ->
	lists:foldl(fun (J, A)-> do_en(A, J) end, Data, Script).

de(Data, []) -> Data;
de(Data, Script) ->
	lists:foldr(fun (J, A)-> do_de(A, J) end, Data, Script).

delta_len(L) ->
	delta_len(L, 0).
delta_len([], N) -> N;
delta_len([{insert, {_, L}, random}|T], N) -> delta_len(T, N+L);
delta_len([{insert, _, Bin}|T], N) -> delta_len(T, N+byte_size(Bin));
delta_len([_|T], N) -> delta_len(T, N).

do_en(Data, {insert, {Pos, Len}, random}) ->
	do_en(Data, {insert, Pos, crypto:rand_bytes(Len)});
do_en(Data, {insert, Pos, Salt}) when Pos>bit_size(Data) ->
	do_en(Data, {insert, Pos rem bit_size(Data), Salt});
do_en(Data, {insert, Pos, Salt}) when Pos<0 ->
	do_en(Data, {insert, Pos rem bit_size(Data) + bit_size(Data), Salt});
do_en(Data, {insert, Pos, Salt}) ->
	<<P1:Pos/bitstring, P2/bitstring>> = Data,
	<<P1/bitstring, Salt/bitstring, P2/bitstring>>;
do_en(Data, {swap, Pos1, Pos2, Len}) when Pos1>bit_size(Data) ->
	do_en(Data, {swap, Pos1 rem bit_size(Data), Pos2, Len});
do_en(Data, {swap, Pos1, Pos2, Len}) when Pos2>bit_size(Data) ->
	do_en(Data, {swap, Pos1, Pos2 rem bit_size(Data), Len});
do_en(Data, {swap, Pos1, Pos2, Len}) when Pos1>Pos2 ->
	do_en(Data, {swap, Pos2, Pos1, Len});
do_en(Data, {swap, Pos1, Pos2, _Len}) when Pos1==Pos2 ->
	Data;
do_en(Data, {swap, Pos1, Pos2, Len}) ->
	Len2 = Pos2-Pos1-Len,
	<<S1:Pos1/bitstring, A:Len/bitstring, S2:Len2/bitstring, B:Len/bitstring, S3/bitstring>> = Data,
	<<S1/bitstring, B/bitstring, S2/bitstring, A/bitstring, S3/bitstring>>;
do_en(Data, _Method) ->
	io:format("Engarble method ~p not supported, yet.\n", [_Method]),
	Data.

do_de(Data, {insert, {Pos, Len}, random}) ->
	do_de(Data, {insert, Pos, crypto:rand_bytes(Len/4)});
do_de(Data, {insert, Pos, Salt}) when Pos>bit_size(Data) ->
	do_de(Data, {insert, Pos rem (bit_size(Data)-bit_size(Salt)), Salt});
do_de(Data, {insert, Pos, Salt}) when Pos<0 ->
	do_de(Data, {insert, bit_size(Data)-bit_size(Salt)+Pos, Salt});
do_de(Data, {insert, Pos, Salt}) ->
	Len = bit_size(Salt),
	<<P1:Pos/bitstring, _:Len/bitstring, P2/bitstring>> = Data,
	<<P1/bitstring, P2/bitstring>>;
do_de(Data, {swap, Pos1, Pos2, Len}) ->
	do_en(Data, {swap, Pos1, Pos2, Len});
do_de(Data, _Method) ->
	io:format("Degarble method ~p not supported, yet.\n", [_Method]),
	Data.

