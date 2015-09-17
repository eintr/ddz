-module(ipaddr).
-export([u32bin_to_addr/1, addr_to_u32bin/1, addrlist_to_bin/1, bin_to_addrlist/1]).
-export([match/2, prefix_parse/1]).

u32bin_to_addr(U32Bin) ->
	<<A:8, B:8, C:8, D:8>> = U32Bin,
	{A,B,C,D}.

addr_to_u32bin({A,B,C,D}) ->
	<<	A:8/unsigned-big-integer,
		B:8/unsigned-big-integer,
		C:8/unsigned-big-integer,
		D:8/unsigned-big-integer>>.

addrlist_to_bin(L) ->
	addrlist_to_bin(L, <<>>).
addrlist_to_bin([], Result) ->
	Result;
addrlist_to_bin([H|T], Result) ->
	addrlist_to_bin(T, <<Result/binary, (addr_to_u32bin(H))/binary>>).

bin_to_addrlist(B) ->
	bin_to_addrlist(B, []).
bin_to_addrlist(<<>>, Result) ->
	Result;
bin_to_addrlist(<<	A:8/unsigned-integer,
					B:8/unsigned-integer,
					C:8/unsigned-integer,
					D:8/unsigned-integer,
					Rest/binary>>, Result) ->
	bin_to_addrlist(Rest, Result++[{A,B,C,D}]).

prefix_parse(Str) when is_list(Str) ->
	Tokens = string:tokens(Str, "/"),
	case length(Tokens) of
		1 ->
			[Prefix] = Tokens,
			case inet:parse_address(Prefix) of
				{ok, Addr} ->
					{ok, {Addr, 32}};
				_ ->
					{error, "Illegal prefix"}
			end;
		2->
			[P, L] = Tokens,
			{Stat, Prefix} = inet:parse_address(P),
			Len = list_to_integer(L),
			if
				Stat == error ->
					{error, "Illegal prefix"};
				Len>32 ->
					{error, "Illegal prefix length"};
				Len<0 ->
					{error, "Illegal prefix length"};
				true ->
					{ok, {Prefix, Len}}
			end;
		_->
			{error, "Unknown prefix format"}
	end.

match({A1, B1, C1, D1}, {{A2, B2, C2, D2}, Len}) ->
	Num  = (A1*256*256*256 + B1*256*256 + C1*256 + D1) bsr (32-Len),
	Masq = (A2*256*256*256 + B2*256*256 + C2*256 + D2) bsr (32-Len),
	if
		Masq == Num ->
			true;
		true ->
			false
	end.

-ifdef(TEST).
-include("test/ipaddr_test.hrl").
-endif.

