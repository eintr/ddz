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

-export([init/1, relay/2, relay/3, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3,
         code_change/4]).

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

init([{PeerID, KSInfo, ServerCFG}]) ->
	LocalID = application:get_env(local_id),
	MTU = 1500-garble:delta_len(KSInfo#msg_body_keysync_info.garble_script),
	SharedKey = KSInfo#msg_body_keysync_info.shared_key,
	{ok, ExtraRouteList} = lists:keyfind(route_prefix, 1, ServerCFG),
	{ok, GS} = lists:keyfind(garble_script, 1, ServerCFG),
	{ok, TunPID} = create_tun(LocalID, PeerID, MTU, ExtraRouteList),
	{ok, relay, {LocalID, TunPID, SharedKey, GS, {1, 0}}}.

relay({up, FromAddr, Body}, {_LocalID, TunPID, SharedKey, _GS, _Repeat}=State) ->
	put(peeraddr, [FromAddr]),
	tuncer:send(TunPID, decrypt(SharedKey, Body#msg_body_data.payload, Body#msg_body_data.len)),
	{next_state, relay, State};
relay(quit, _State) ->
	{stop, normal};
relay(_Event, State) ->
	io:format("conn/relay: Unknown event: ~p\n", [_Event]),
    {next_state, relay, State}.

relay(stat, _From, State) ->
	{reply, todo, relay, State};
relay(_Event, _From, State) ->
	io:format("Unknown event: ~p from ~p\n", [_Event, _From]),
    {reply, ok, relay, State}.

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
	[DAddr] = get(peeraddr),
	echo_send(DAddr, Repeat, msg:encode(Msg)),
	{next_state, relay, State};
handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.

terminate(_Reason, _StateName, {_ConnID, TunPID}) ->
	ok = tuncer:close(TunPID),
	ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------
create_tun(<<A1:8, A2:8, A3:8, A4:8>>, <<B1:8, B2:8, B3:8, B4:8>>, MTU, ExtraRouteList) ->
	{ok, TunPID} = tuncer:create([], [tun, {active, true}]),
	IFName = binary:bin_to_list(tuncer:devname(TunPID)),
	{0, _} = util:system(io_lib:format("ip address add dev ~s ~p.~p.~p.~p peer ~p.~p.~p.~p", [IFName, A1, A2, A3, A4, B1, B2, B3, B4])),
	{0, _} = util:system(io_lib:format("ip link set dev ~s up", [IFName])),
	{0, _} = util:system(io_lib:format("ip link set dev ~s mtu ~p", [IFName, MTU])),
	lists:foreach(fun (default) ->
						  util:system(io_lib:format("ip route add default dev ~s", [IFName]));
					  ({{A,B,C,D}, L}) ->
						  util:system(io_lib:format("ip route add ~p.~p.~p.~p/~p dev ~s", [A,B,C,D,L, IFName]))
				  end, ExtraRouteList),
	put(tun_ifname, IFName),
	io:format("~p: ~s is configured an activated.\n", [?MODULE, get(tun_ifname)]),
	{ok, TunPID}.

encrypt(Key, Tip) when byte_size(Tip)<8 ->
	crypto:block_encrypt(Key, <<Tip/binary, (binary:copy(<<0>>, 8-byte_size(Tip)))/binary>>);
encrypt(Key, <<Block:8/binary, Rest/binary>>) ->
	<<(crypto:block_encrypt(Key, Block))/binary, (encrypt(Key, Rest))/binary>>.

decrypt(Key, Bin, Len) ->
	binary:part(decrypt(Key, Bin), 0, Len).
decrypt(_, <<>>) -> <<>>;
decrypt(Key, <<Block:8/binary, Rest/binary>>) ->
	<<(crypto:block_encrypt(Key, Block))/binary, (decrypt(Key, Rest))/binary>>.

echo_send(DAddr, {1, _}, Bin) ->
	gen_server:cast(tranceiver, {down, DAddr, Bin});
echo_send(DAddr, {N, Delay}, Bin) ->
	timer:apply_after(Delay*(N-1), gen_server, cast, [tranceiver, {down, DAddr, Bin}]),
	echo_send(DAddr, {N-1, Delay}, Bin).

