-module(kv_store).
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
	PostFix = case application:get_application() of
				  {ok, AppName} -> atom_to_list(AppName);
				  U -> atom_to_list(U)
			  end,
	{ok, Dets} = dets:open_file(?SERVER, [{file, "stored_dict_"++PostFix++".dets"}]),
	{ok, {Dets, dict:new()}}.

handle_call({lookup, Key}, _From, {Dets, Dict}) ->
	V = case dict:find(Key, Dict) of
			{ok, Value} -> {ok, Value};
			error ->
				case dets:lookup(Dets, Key) of
					[{Key, Value}] ->
						{ok, Value};
					[] -> not_found;
					{error, _} ->
						not_found
				end
		end,
	{reply, V, {Dets, Dict}};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({save_temp, Key, Value}, {Dets, Dict}) ->
	{noreply, {Dets, dict:store(Key, Value, Dict)}};
handle_cast({save_perm, Key, Value}, {Dets, Dict}) ->
	dets:insert(Dets, {Key, Value}),
	{noreply, {Dets, Dict}};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, {Dets, _}) ->
	dets:close(Dets),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

