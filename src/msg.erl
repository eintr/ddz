-module(msg).
-export([encode/1, decode/1, encrypt_keysync/2, decrypt_keysync/2]).

-include("msg.hrl").

encode(Msg) ->
	Body = Msg#msg.body,
	case Msg#msg.code of
		?CODE_DATA ->
			BodyBin = <<(Body#msg_body_data.src_id):32/unsigned-big-integer,
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
			BodyBin = <<(Body#msg_body_connect.server_id):32/unsigned-big-integer>>,
			{ok, << (Msg#msg.code):8, BodyBin/binary>>};
		?CODE_REJECT ->
			BodyBin = <<
						(Body#msg_body_reject.client_id):32/unsigned-big-integer,
						(list_to_binary(Body#msg_body_reject.reason))/binary >>,
			{ok, << (Msg#msg.code):8, BodyBin/binary>>};
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
			<<SrcID:32/unsigned-big-integer,
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
			<<ServerID:32/unsigned-big-integer>> = BodyBin,
			Body = #msg_body_connect{server_id=ServerID},
			{ok, #msg{code=Code, body=Body}};
		?CODE_REJECT ->
			<<
			  ClientID:32/unsigned-big-integer,
			  Reason/binary
			>> = BodyBin,
			Body = #msg_body_reject{client_id=ClientID, reason=binary_to_list(Reason)},
			{ok, #msg{code=Code, body=Body}};
		_Code ->
			io:format("Unknown Msg code ~p\n", [_Code]),
			{error, "Unknown code."}
	end.

encrypt_keysync(Info, {_PrivK, PubK}) ->
	PlainBin = <<	(Info#msg_body_keysync_info.client_id):32/unsigned-big-integer,
					(Info#msg_body_keysync_info.shared_key):?SHAREDKEY_LENGTH/binary,
					(list_to_binary(Info#msg_body_keysync_info.username)):32/binary,
					(list_to_binary(Info#msg_body_keysync_info.password)):32/binary,
					(list_to_binary(Info#msg_body_keysync_info.garble_script))/binary >>,
	MD5 = crypto:hash(md5, PlainBin),
	CryptedBin = crypto:public_encrypt(rsa, PlainBin, PubK, rsa_pkcs1_padding),
	#msg_body_keysync{info=CryptedBin, md5=MD5}.

decrypt_keysync(MsgBody, {PrivK, _PubK}) ->
	CryptedBin = MsgBody#msg_body_keysync.info,
	MD5 = MsgBody#msg_body_keysync.md5,
	PlainBin = crypto:private_decrypt(rsa, CryptedBin, PrivK, rsa_pkcs1_padding),
	case crypto:hash(md5, PlainBin) of
		MD5 ->
			<<ClientID:32/unsigned-big-integer,
			  SharedK:?SHAREDKEY_LENGTH/binary,
			  Username:32/binary,
			  Password:32/binary,
			  GSbin/binary >> = PlainBin,
			case eval_str(binary_to_list(GSbin)) of
				{ok, GSript} ->
					{ok, #msg_body_keysync_info{ client_id=ClientID,
												 shared_key=SharedK,
												 username=binary_to_list(Username),
												 password=binary_to_list(Password),
												 garble_script=GSript}};
				{error, Reason} ->
					{error, "Garble script "++Reason}
			end;
		_ ->
			{error, "decrypt_keysync() failed."}
	end.

eval_str(S) ->
	case erl_scan:string(S) of
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

