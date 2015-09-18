-module(msg).
-export([encode/1, decode/1, encrypt_keysync/2, decrypt_keysync/2]).

-include("msg.hrl").

encode(Msg) ->
	Body = Msg#msg.body,
	case Msg#msg.code of
		?CODE_DATA ->
			BodyBin = <<(Body#msg_body_data.src_id):4/binary,
						(Body#msg_body_data.len):16/unsigned-big-integer,
						(Body#msg_body_data.payload)/binary>>,
			{ok, << (Msg#msg.code):8,BodyBin/binary >>};
		?CODE_CRTREQ ->
			{ok, <<	(Msg#msg.code):8, 0:32 >>};
		?CODE_CRT ->
			{ok, << (Msg#msg.code):8, (Body#msg_body_crt.x509)/binary >>};
		?CODE_KEYSYNC ->
			BodyBin = <<(Body#msg_body_keysync.md5):16/binary,
						(Body#msg_body_keysync.info)/binary >>,
			{ok, << (Msg#msg.code):8, BodyBin/binary>>};
		?CODE_CONNECT ->
			BodyBin = <<(Body#msg_body_connect.server_id):4/binary>>,
			{ok, << (Msg#msg.code):8, BodyBin/binary>>};
		?CODE_REJECT ->
			BodyBin = <<
						(Body#msg_body_reject.client_id):4/binary,
						(list_to_binary(Body#msg_body_reject.reason))/binary >>,
			{ok, << (Msg#msg.code):8, BodyBin/binary>>};
		?CODE_REJECT ->
			BodyBin = <<(Body#msg_body_reset.peer_id)/binary>>,
			{ok, <<(Msg#msg.code):8, BodyBin/binary>>};
		?CODE_CLOSE ->
			BodyBin = <<>>,
			{ok, << (Msg#msg.code):8, BodyBin/binary>>};
		_Code ->
			{error, "Unknown message code."}
	end.

decode(MsgBin) ->
	<<Code:8/big-integer, BodyBin/binary>> = MsgBin,
	case Code of
		?CODE_DATA ->
			<<SrcID:4/binary,
			  Len:16/unsigned-big-integer,
			  Data/binary>> = BodyBin,
			{ok, #msg{code=Code, body=#msg_body_data{src_id=SrcID, len=Len, payload=Data}}};
		?CODE_CRTREQ ->
			Body = #msg_body_crtreq{type=0},
			{ok, #msg{code=Code, body=Body}};
		?CODE_CRT ->
			{ok, #msg{code=Code, body=#msg_body_crt{x509=BodyBin}}};
		?CODE_KEYSYNC ->
			<<MD5:16/binary,
			  Info/binary >> = BodyBin,
			Body = #msg_body_keysync{
					  info = Info,
					  md5 = MD5
					 },
			{ok, #msg{code=Code, body=Body}};
		?CODE_CONNECT ->
			<<ServerID:4/binary>> = BodyBin,
			Body = #msg_body_connect{server_id=ServerID},
			{ok, #msg{code=Code, body=Body}};
		?CODE_REJECT ->
			<<ClientID:4/binary,
			  Reason/binary	>> = BodyBin,
			Body = #msg_body_reject{client_id=ClientID, reason=binary_to_list(Reason)},
			{ok, #msg{code=Code, body=Body}};
		?CODE_RESET ->
			<<PeerID:4/binary>> = BodyBin,
			Body = #msg_body_reset{peer_id=PeerID},
			{ok, #msg{code=Code, body=Body}};
		_Code ->
			io:format("Unknown Msg code ~p\n", [_Code]),
			{error, "Unknown code."}
	end.

encrypt_keysync(Info, {_PrivK, PubK}) ->
	PlainBin = <<	(Info#msg_body_keysync_info.client_id):4/binary,
					(Info#msg_body_keysync_info.shared_key):8/binary,
					(str_to_nbin(Info#msg_body_keysync_info.username, 32)):32/binary,
					(str_to_nbin(Info#msg_body_keysync_info.password, 32)):32/binary,
					(list_to_binary(
						lists:flatten(
							io_lib:format("~p", 
								[Info#msg_body_keysync_info.garble_script]	))))/binary
				>>,
	MD5 = crypto:hash(md5, PlainBin),
	CryptedBin = public_key:encrypt_public(PlainBin, PubK),
	#msg_body_keysync{info=CryptedBin, md5=MD5}.

str_to_nbin(Str, Len) when length(Str) >= Len ->
	binary:part(list_to_binary(Str), 0, Len);
str_to_nbin(Str, Len) when length(Str) < Len ->
	<<(list_to_binary(Str))/binary, (binary:copy(<<0>>, Len-length(Str)))/binary>>.

decrypt_keysync(MsgBody, {PrivK, _PubK}) ->
	CryptedBin = MsgBody#msg_body_keysync.info,
	MD5 = MsgBody#msg_body_keysync.md5,
	PlainBin = public_key:decrypt_private(CryptedBin, PrivK),
	case crypto:hash(md5, PlainBin) of
		MD5 ->
			<<ClientID:4/binary,
			  SharedK:?SHAREDKEY_LENGTH/binary,
			  Username:32/binary,
			  Password:32/binary,
			  GSbin/binary >> = PlainBin,
			case eval_str(binary_to_list(GSbin)) of
				{ok, GSript} ->
					{ok, #msg_body_keysync_info{ client_id=ClientID,
												 shared_key=SharedK,
												 username=string:strip(binary_to_list(Username), right, 0),
												 password=string:strip(binary_to_list(Password), right, 0),
												 garble_script=GSript}};
				{error, Reason} ->
					{error, "Garble script "++Reason}
			end;
		_ ->
			{error, "decrypt_keysync() failed."}
	end.

eval_str(S) ->
	case erl_scan:string(S++".") of
		{ok, Scaned, _} ->
			case erl_parse:parse_exprs(Scaned) of
				{ok, Parsed} ->
					case erl_eval:exprs(Parsed, []) of
						{value, V, _} ->
							{ok, V};
						_ ->
							{error, "evaluate failed."}
					end;
				_ ->
					{error, "parse failed."}
			end;
		_ ->
			{error, "scan failed."}
	end.

-ifdef(TEST).
-include("test/msg_test.hrl").
-endif.

