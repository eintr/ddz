-module(authserver).
-behaviour(gen_server).
-define(SERVER, ?MODULE).

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
	case application:get_env(accounts) of
		{ok, open} ->
			{ok, open};
		{ok, List} ->
			{ok, List}
	end.

handle_call({auth, _, _}, _From, open) ->
	{reply, {pass, {}}, open};
handle_call({auth, Username, Password}, _From, AccList) ->
	case lists:keyfind(Username, 1, AccList) of
		{Username, Password, ExtraInfo} ->
			{reply, {pass, ExtraInfo}, AccList};
		_ ->
			{reply, {fail, "Login failed."}, AccList}
	end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

