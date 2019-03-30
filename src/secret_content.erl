-module(secret_content).

-behaviour(cowboy_handler).

-export([init/2]).

init(Req0, Opts) ->
    Body = <<"<html><title>Secret content</title><body>
    <h1>This is a secret content</h1>
    <iframe width=\"560\" height=\"315\" src=\"https://www.youtube.com/embed/-H-iEWQmQ7I\" frameborder=\"0\" allow=\"accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture\" allowfullscreen></iframe>
    </body></html>">>,
	Req = cowboy_req:reply(200, #{
		<<"content-type">> => <<"text/html">>
	}, Body, Req0),
    {ok, Req, Opts}.