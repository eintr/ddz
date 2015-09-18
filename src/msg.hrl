-define(CODE_DATA, 0).
-define(CODE_CRTREQ, 1).
-define(CODE_CRT, 2).
-define(CODE_KEYSYNC, 3).
-define(CODE_CONNECT, 4).
-define(CODE_REJECT, 5).
-define(CODE_RESET, 6).
-define(CODE_PING, 11).
-define(CODE_PONG, 12).
-define(CODE_CLOSE, 20).

-define(CONNID_CTRL, 16#00000000).
-define(CONNID_INVAL, 16#ffffffff).

-define(SALT_LENGTH, 8).
-define(SHAREDKEY_LENGTH, 8).

-record(msg_body_data, {
		  src_id,
		  len,
		  payload
		 }).

-record(msg_body_crtreq, {
		  type
		 }).

-record(msg_body_crt, {
		  x509
		 }).

-record(msg_body_keysync_info, {client_id, shared_key, username, password, garble_script}).

-record(msg_body_keysync, {
		  info,
		  md5
		 }).

-record(msg_body_connect, {
		  server_id
		 }).

-record(msg_body_reject, {
		  client_id,
		  reason
		 }).

-record(msg_body_reset, {
		  peer_id
		 }).

-record(msg_body_ping, {
		  seq,
		  timestamp
		 }).

-record(msg_body_pong, {
		  seq,
		  timestamp
		 }).

-record(msg, {
		  code,
		  body
		 }).

