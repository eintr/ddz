-include_lib("eunit/include/eunit.hrl").
 
convertion_test() ->
	?assert(ipaddr:u32bin_to_addr(<<1,2,3,4>>) =:= {1,2,3,4}),
	?assert(ipaddr:u32bin_to_addr(<<0,0,0,0>>) =:= {0,0,0,0}).

prefix_parse_test() ->
	?assert(ipaddr:prefix_parse("1.2.3.4/24") =:= {ok, {{1,2,3,4}, 24}}),
	?assert(ipaddr:prefix_parse("1.2.3.4") =:= {ok, {{1,2,3,4}, 32}}).

cidr_match_test() ->
	?assert(ipaddr:match({1,2,3,4}, {{1,2,3,5}, 24})),
	?assert(ipaddr:match({1,2,3,4}, {{2,2,3,5}, 8}) =:= false).
 
