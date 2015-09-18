-module(connection).
-behaviour(gen_fsm).
-define(SERVER, ?MODULE).

-include("msg.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start/1, start_link/1]).

%% ------------------------------------------------------------------
%% gen_fsm Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3,
         code_change/4]).
-export([relay/2, relay/3, pending_reset/2]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start(ConnCfg) ->
    gen_fsm:start(?MODULE, [ConnCfg], []).
start_link(ConnCfg) ->
    gen_fsm:start_link(?MODULE, [ConnCfg], []).

%% ------------------------------------------------------------------
%% gen_fsm Function Definitions
%% ------------------------------------------------------------------

init([{PeerID, PeerAddr, SharedKey, GS, RouteList, ServerCFG}]) ->
	{ok, LocalID} = application:get_env(local_id),
	MTU = 1500-garble:delta_len(GS),
	put(peeraddr, PeerAddr),
	put(peerid, PeerID),
	put(servercfg, ServerCFG),
	{ok, TunPID} = create_tun(LocalID, PeerID, MTU, RouteList),
	{ok, relay, {LocalID, TunPID, SharedKey, GS, {1, 0}}}.

relay(quit, State) ->
	{stop, normal, State};
relay({reset, NewAddr}, State) ->
	case get(servercfg) of
		passive ->
			gen_server:call(dispatcher, {destroy_conn, get(peerid)}),
			{next_state, relay, State};
		ServerCFG ->
			gen_server:call(connection_control, {connect_req, lists:keyreplace(addr, 1, ServerCFG, {addr, NewAddr})}),
			{next_state, pending_reset, State}
	end;
relay({update, NewAddr, NewKey}, {_LocalID, TunPID, _SharedKey, _GS, _Repeat}) ->
	io:format("~p: Connection with ~p updated to ~p, Key=~p\n", [?MODULE, get(peeraddr), NewAddr, NewKey]),
	put(peeraddr, NewAddr),
	{next_state, relay, {_LocalID, TunPID, NewKey, _GS, _Repeat}};
relay({up, FromAddr, Body}, {_LocalID, TunPID, SharedKey, _GS, _Repeat}=State) ->
	put(peeraddr, FromAddr),
	tuncer:send(TunPID, decrypt(SharedKey, Body#msg_body_data.payload, Body#msg_body_data.len)),
	{next_state, relay, State};
relay(_Event, State) ->
	io:format("conn/relay: Unknown event: ~p\n", [_Event]),
    {next_state, relay, State}.

relay(stat, _From, State) ->
	{reply, todo, relay, State};
relay(_Event, _From, State) ->
	io:format("Unknown event: ~p from ~p\n", [_Event, _From]),
    {reply, ok, relay, State}.

pending_reset(quit, State) ->
	{stop, normal, State};
pending_reset({update, NewAddr, NewKey}, {_LocalID, TunPID, _SharedKey, _GS, _Repeat}) ->
	io:format("~p: Connection with ~p reset over\n", [?MODULE, TunPID]),
	put(peeraddr, NewAddr),
	{next_state, relay, {_LocalID, TunPID, NewKey, _GS, _Repeat}};
pending_reset(_Event, State) ->
    {next_state, pending_reset, State}.

handle_event(_Event, StateName, State) ->
	{next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {reply, ok, StateName, State}.

handle_info({tuntap, TunPID, TunPktBin}, relay, {LocalID, TunPID, SharedKey, _GS, Repeat}=State) ->
	CryptedBin = encrypt(SharedKey, TunPktBin),
	Msg = #msg{ code=?CODE_DATA,
				body=#msg_body_data{ src_id=LocalID,
									 len=byte_size(TunPktBin),
									 payload=CryptedBin}},
	DAddr = get(peeraddr),
	{ok, MsgBin} = msg:encode(Msg),
	echo_send(DAddr, Repeat, MsgBin),
	{next_state, relay, State};
handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.

terminate(_Reason, _StateName, {_LocalID, TunPID, _SharedKey, _GS, _Repeat}) ->
	ok = tuncer:destroy(TunPID),
	ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------
create_tun(<<A1:8, A2:8, A3:8, A4:8>>, <<B1:8, B2:8, B3:8, B4:8>>, MTU, ExtraRouteList) ->
	{ok, TunPID} = tuncer:create([], [tun, {active, true}]),
	IFName = binary:bin_to_list(tuncer:devname(TunPID)),
	{0, _} = system(io_lib:format("ip address add dev ~s ~p.~p.~p.~p peer ~p.~p.~p.~p", [IFName, A1, A2, A3, A4, B1, B2, B3, B4])),
	{0, _} = system(io_lib:format("ip link set dev ~s up", [IFName])),
	{0, _} = system(io_lib:format("ip link set dev ~s mtu ~p", [IFName, MTU])),
	lists:foreach(fun (default) ->
						  system(io_lib:format("ip route add default dev ~s", [IFName]));
					  ({{A,B,C,D}, L}) ->
						  system(io_lib:format("ip route add ~p.~p.~p.~p/~p dev ~s", [A,B,C,D,L, IFName]))
				  end, ExtraRouteList),
	put(tun_ifname, IFName),
	io:format("~p: ~s is configured an activated.\n", [?MODULE, get(tun_ifname)]),
	{ok, TunPID}.

encrypt(Key, Tip) when byte_size(Tip)<8 ->
	crypto:block_encrypt(blowfish_ecb, Key, <<Tip/binary, (binary:copy(<<0>>, 8-byte_size(Tip)))/binary>>);
encrypt(Key, <<Block:8/binary, Rest/binary>>) ->
	<<(crypto:block_encrypt(blowfish_ecb, Key, Block))/binary, (encrypt(Key, Rest))/binary>>.

decrypt(Key, Bin, Len) ->
	binary:part(decrypt(Key, Bin), 0, Len).
decrypt(_, <<>>) -> <<>>;
decrypt(Key, <<Block:8/binary, Rest/binary>>) ->
	<<(crypto:block_decrypt(blowfish_ecb, Key, Block))/binary, (decrypt(Key, Rest))/binary>>.

echo_send(DAddr, {1, _}, Bin) ->
	gen_server:cast(tranceiver, {down, DAddr, Bin});
echo_send(DAddr, {N, Delay}, Bin) ->
	timer:apply_after(Delay*(N-1), gen_server, cast, [tranceiver, {down, DAddr, Bin}]),
	echo_send(DAddr, {N-1, Delay}, Bin).


system(Str) ->
	PidStr = lists:flatten(io_lib:format("~p", [self()])),
	PidSalt = string:strip(string:strip(PidStr, left, $<), right, $>),
	TimeSalt = string:strip(
			string:strip(
				lists:flatten(io_lib:format("~p", [os:timestamp()])),
				left, ${),
			right, $}),
	TmpFname = "/tmp/wormhole."++ os:getpid() ++ "." ++ PidSalt ++ TimeSalt,
	CMD = lists:flatten(Str) ++ " > " ++ TmpFname ++ " ; echo $?",
	Codeout = os:cmd(CMD),
	Code = list_to_integer(string:strip(Codeout, right, 10)),
	{ok, OutPutBin} = file:read_file(TmpFname),
	file:delete(TmpFname),
	{Code, binary:bin_to_list(OutPutBin)}.

