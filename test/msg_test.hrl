-include_lib("eunit/include/eunit.hrl").
 
data_decode_test() ->
	M = #msg{code=?CODE_DATA,
			 body=#msg_body_data{src_id=16#12345678, data = <<"This is a test content.">>}},
	B = <<?CODE_DATA:8/unsigned-big-integer, 16#12345678:32, <<"This is a test content.">>/binary>>,
	{ok, R} = msg:encode(M),
	?assert( R =:= B ).

data_encode_test() ->
	M = #msg{code=?CODE_DATA,
			 body=#msg_body_data{src_id=16#12345678, data = <<"This is a test content.">>}},
	B = <<?CODE_DATA:8/unsigned-big-integer, 16#12345678:32, <<"This is a test content.">>/binary>>,
	{ok, R} = msg:decode(B),
	?assert( R =:= M ).

keysync_encode_test() ->
	M = #msg{
		  code=?CODE_KEYSYNC,
		  body= #msg_body_keysync{
								  client_id = 1,
								  md5 = binary:copy(<<"M">>, 16),
								  crypted_key = binary:copy(<<"K">>, 64),
								  username = "user1" }},
	TARGET = <<	?CODE_KEYSYNC:8,
				1:32/unsigned-big-integer,
				(binary:copy(<<"K">>, 64))/binary,
				(binary:copy(<<"M">>, 16))/binary,
				<<"user1">>/binary
			 >>,
	{ok, B} = msg:encode(M),
	?assert( B =:= TARGET).

keysync_decode_test() ->
	M = #msg{
		  code=?CODE_KEYSYNC,
		  body= #msg_body_keysync{
								  client_id = 1,
								  md5 = binary:copy(<<"M">>, 16),
								  crypted_key = binary:copy(<<"K">>, 64),
								  username = "user1" }},
	B = <<	?CODE_KEYSYNC:8,
				1:32/unsigned-big-integer,
				(binary:copy(<<"K">>, 64))/binary,
				(binary:copy(<<"M">>, 16))/binary,
				<<"user1">>/binary
			 >>,
	{ok, R} = msg:decode(B),
	io:format("Decode output: ~p\n", [R]),
	io:format("Expected: ~p\n", [M]),
	?assert( M =:= R).

