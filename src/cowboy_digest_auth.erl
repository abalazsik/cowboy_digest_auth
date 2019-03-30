-module(cowboy_digest_auth).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    Dispatch = cowboy_router:compile([{'_',[
		{"/", secret_content, []}
    ]}]),

    cowboy:start_clear(http,
	[
        {port, 8080}
    ],
	#{
        env => #{dispatch => Dispatch},
        middlewares => [digest_middleware, cowboy_router, cowboy_handler]
    }).

stop(_State) ->
    cowboy:stop_listener(http).

