-module(connection_control).
-behaviour(gen_fsm).
-define(SERVER, ?MODULE).

-include("msg.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).

%% ------------------------------------------------------------------
%% gen_fsm Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_event/3, handle_sync_event/4, handle_info/3,
		 terminate/3, code_change/4]).
-export([loop/2, loop/3]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    gen_fsm:start_link({local, ?SERVER}, ?MODULE, [], []).

%% ------------------------------------------------------------------
%% gen_fsm Function Definitions
%% ------------------------------------------------------------------

init([]) ->
	{ok, X509Fname} = application:get_env(rsa_crt),
	{ok, Crt} = load_x509(X509Fname),
	put(rsa_crt, Crt),
	{'RSAPublicKey', PubKey, _} = extract_pubkey(Crt),
	put(rsa_pubkey, PubKey),
	{ok, KeyFname} = application:get_env(rsa_key),
	{ok, PrivKey} = load_privkey(KeyFname),
	put(rsa_privkey, PrivKey),
	io:format("~p: is up.\n", [?MODULE]),
	{ok, loop, {[]}}.

loop({connect_req, ServerCFG}, State) ->
	{addr, {ServerIP, ServerPort}} = lists:keyfind(addr, 1, ServerCFG),
	case gen_server:call(kv_store, {lookup, {rsa, ServerIP}}) of
		{ok, {_Crt, Pubkey}} ->
			io:format("~p: Going to connect to ~p\n", [?MODULE, ServerCFG]),
			{ok, LocalID} = application:get_env(local_id),
			SharedKey = crypto:rand_bytes(?SHAREDKEY_LENGTH),
			{account, {Username, Password}} = lists:keyfind(account, 1, ServerCFG),
			{garble_script, GS} = lists:keyfind(garble_script, 1, ServerCFG),
			KSInfo = #msg_body_keysync_info{ client_id = LocalID,
											 shared_key = SharedKey,
											 username = Username,
											 password = Password,
											 garble_script = GS},
			put({pending_keysync, ServerIP, ServerPort}, {spawn(fun ()-> pending_keysync({ServerIP, ServerPort}, KSInfo, ServerCFG) end)}),
			KSyncMsg = #msg{ code = ?CODE_KEYSYNC,
							 body = msg:encrypt_keysync(KSInfo, {<<>>, Pubkey})
						   },
			send_msg({ServerIP, ServerPort}, KSyncMsg);
		not_found ->
			io:format("~p: Request crt before connect to ~p\n", [?MODULE, ServerIP]),
			Pid = spawn(fun ()->pending_crtreq(ServerCFG) end),
			put({pending_crtreq, ServerIP}, Pid)
	end,
	{next_state, loop, State};
loop({keysync_timeout, {IP, Port}}, State) ->
	io:format("Keysync timed out.\n"),
	erase({pending_keysync, IP, Port}),
	{next_state, loop, State};
loop({crtreq_timeout, ServerCFG}, State) ->
	{addr, {ServerIP, _}} = lists:keyfind(addr, 1, ServerCFG),
	io:format("RequestCrt timed out.\n"),
	erase({pending_crtreq, ServerIP}),
	{next_state, loop, State};
loop({up, FromAddr, Msg}, State) ->
	msg_process(FromAddr, Msg),
	{next_state, loop, State};
loop(_Event, State) ->
	io:format("conn/control: Unknown event: ~p\n", [_Event]),
	{next_state, loop, State}.

loop(_Event, _From, State) ->
	io:format("Unknown event: ~p from ~p\n", [_Event, _From]),
    {reply, unknown_event, loop, State}.

handle_event(Event, StateName, State) ->
	io:format("~p: Don't know how to process all_state_event: ~p\n", [?MODULE, Event]),
	{next_state, StateName, State}.

handle_sync_event(Event, _From, StateName, State) ->
	io:format("~p: Don't know how to process sync_event: ~p\n", [?MODULE, Event]),
    {reply, ok, StateName, State}.

handle_info(Info, StateName, State) ->
	io:format("~p: Don't know how to process info: ~p\n", [?MODULE, Info]),
    {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
	ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------
msg_process(FromAddr, #msg{code=?CODE_CRTREQ, body=_}) ->
	Msg = case get(cache_msg_crt) of
			  undefined ->
				  M = #msg{ code=?CODE_CRT,
							body=#msg_body_crt{ x509=get(rsa_crt)} },
				  put(cache_msg_crt, M),
				  M;
			  M -> M
		  end,
	send_msg(FromAddr, Msg);
msg_process({IP, _}, #msg{code=?CODE_CRT, body=Body}) ->
	CRT = Body#msg_body_crt.x509,
	case get({pending_crtreq, IP}) of
		undefined ->
			io:format("Ignored an unexpected CRT.\n");
		Pid ->
			case verify_crt(CRT) of
				pass ->
					PubKey = extract_pubkey(CRT),
					gen_server:cast(kv_store, {save_perm, {rsa, IP}, {CRT, PubKey}}),
					erase({pending_crtreq, IP}),
					Pid ! crt_ready;
				_ ->
					io:format("Ignored an illegal CRT.\n")
			end
	end;
msg_process(FromAddr, #msg{code=?CODE_KEYSYNC, body=Body}) ->
	case msg:decrypt_keysync(Body, {get(rsa_privkey), <<>>}) of
		{ok, PlainInfo} ->
			case gen_server:call(authserver, { auth,
											   PlainInfo#msg_body_keysync_info.username,
											   PlainInfo#msg_body_keysync_info.password}) of
				{pass, _ExtraInfo} ->
					gen_server:call(dispatcher, {create_conn, {	PlainInfo#msg_body_keysync_info.client_id,
															PlainInfo#msg_body_keysync_info.shared_key,
															PlainInfo#msg_body_keysync_info.garble_script,
															[]}}),
					{ok, <<LocalID:32/unsigned-big-integer>>} = application:get_env(local_id),
					send_msg(FromAddr, #msg{code=?CODE_CONNECT,
										    body=#msg_body_connect{server_id=LocalID}});
				{fail, Reason} ->
					io:format("Login failed: ~s\n", [Reason])
			end;
		{error, Reason} ->
			io:format("keysync msg error: ~s\n", [Reason])
	end;
msg_process({PeerIP, PeerPort}, #msg{code=?CODE_CONNECT, body=_}) ->
	case get({pending_keysync, PeerIP, PeerPort}) of
		{Pid} ->
			erase({pending_keysync, PeerIP, PeerPort}),
			Pid ! connected;
		undefined ->
			io:format("Ignored an unexpected CONNECT.\n")
	end;
msg_process(_FromAddr, #msg{code=?CODE_PING, body=_}) ->
	io:format("TODO: CODE_PING is not implemented yet, msg dropped.\n");
msg_process(_FromAddr, #msg{code=CODE, body=_}) ->
	io:format("Control doesn't deal with msg code=~p, dropped.\n", [CODE]).

pending_keysync({IP, Port}, KSInfo, ServerCFG) ->
	receive
		connected ->
			RouteList = case lists:keyfind(route_prefix, 1, ServerCFG) of
							{ok, L} -> L;
							_ -> []
						end,
			gen_server:call(dispatcher, {create_conn, {	KSInfo#msg_body_keysync_info.client_id,
														KSInfo#msg_body_keysync_info.shared_key,
														KSInfo#msg_body_keysync_info.garble_script,
														RouteList}})
	after 3000 ->
		gen_fsm:send_event(connection_control, {keysync_timeout, {IP, Port}})
	end.

pending_crtreq(ServerCFG) ->
	{addr, Addr} = lists:keyfind(addr, 1, ServerCFG),
	send_msg(Addr, #msg{ code=?CODE_CRTREQ, body=#msg_body_crtreq{type=0}}),
	receive
		crt_ready ->
			gen_fsm:send_event(connection_control, {connect_req, ServerCFG})
	after 3000 ->
			  io:format("~p: feeding connection_control crtreq_timeout event.\n", [?MODULE]),
			  gen_fsm:send_event(connection_control, {crtreq_timeout, ServerCFG})
	end.

send_msg(Addr, Msg) ->
	io:format("~p: Send {~p,...} to ~p\n", [?MODULE, Msg#msg.code, Addr]),
	{ok, Bin} = msg:encode(Msg),
	gen_server:cast(tranceiver, {down, Addr, Bin}).

verify_crt(_CertBin) -> % TODO
	pass.

load_x509(Fname) ->
	{ok, PemBin} = file:read_file(Fname),
	[{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(PemBin),
	{ok, Cert}.

extract_pubkey(CertBin) ->
	CertRec = public_key:pkix_decode_cert(CertBin, otp),
	((CertRec#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.subjectPublicKeyInfo)#'OTPSubjectPublicKeyInfo'.subjectPublicKey.

load_privkey(Fname) ->
	{ok, PemBin} = file:read_file(Fname),
	[RSAEntry] = public_key:pem_decode(PemBin),
	{ok, public_key:pem_entry_decode(RSAEntry)}.

