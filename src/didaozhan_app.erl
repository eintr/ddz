-module(didaozhan_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
	case os:type() of
		{unix, linux} ->
			didaozhan_sup:start_link();
		T ->
			io:format("System ~p is not supported, yet.\n", [T]),
			{error, "OS not supported"}
	end.

stop(_State) ->
    ok.
