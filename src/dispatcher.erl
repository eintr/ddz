-module(dispatcher).
-behaviour(gen_server).
-define(SERVER, ?MODULE).

-include("msg.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([]) ->
	{ok, Pid} = connection_control:start_link(),
	put(?CONNID_CTRL, {Pid}),
	io:format("~p: inited.\n", [?MODULE]),
	{ok, PeerList} = application:get_env(connect_peers),
	lists:foreach(fun (S)-> gen_fsm:send_event(Pid, {connect_req, S}) end, PeerList),
	{ok, {}}.

handle_call({destroy_conn, ConnID}, _From, State) ->
	case get(ConnID) of
		{Pid} ->
			gen_fsm:send_event(Pid, quit);
		undefined ->
			io:format("~p: connection: ~p not exsist, can't delete.\n", [?MODULE, ConnID])
	end,
	{reply, todo, State};
handle_call({create_conn, ConnCfg}, _From, State) ->
	{ok, Pid} = connection:start(ConnCfg),
	{ConnID, _, _, _, _} = ConnCfg,
	put(ConnID, {Pid}),
	io:format("~p: Registered ~p for conn ~p\n", [?MODULE, Pid, ConnID]),
	{reply, ok, State};
handle_call(_Request, _From, State) ->
	io:format("~p: Don't know how to deal with call ~p\n", [?SERVER, _Request]),
    {reply, ok, State}.

handle_cast({up, FromAddr, WireBin}, State) ->
	Msg = msg:decode(WireBin),
	case Msg#msg.code of
		?CODE_DATA ->
			case get((Msg#msg.body)#msg_body_data.src_id) of
				{Pid} ->
					gen_fsm:send_event(Pid, {up, FromAddr, Msg#msg.body});
				undefined ->
					io:format("Got data from unknown id: ~p, drop it\n", [(Msg#msg.body)#msg_body_data.src_id])
			end;
		_ ->
			{Pid} = get(?CONNID_CTRL),
			gen_fsm:send_event(Pid, {up, FromAddr, Msg})
	end,
	{noreply, State};
handle_cast(_Msg, State) ->
	io:format("~p: Don't know how to deal with cast ~p\n", [?SERVER, _Msg]),
    {noreply, State}.

handle_info(_Info, State) ->
	io:format("~p: Don't know how to deal with info ~p\n", [?SERVER, _Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

