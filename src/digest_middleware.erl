-module(digest_middleware).

-export([execute/2]).

-behaviour(cowboy_middleware).

-define(REALM, "cowboy").

getPasswordByUsername(<<"username">>) -> "password"; %%add multiple users here
getPasswordByUsername(_) -> unknown.

execute(Req, State) ->
    case isPublic(cowboy_req:path(Req)) of
      true ->
        {ok, Req, State};
      false ->
          digestAuthentication(Req, State)
    end.

digestAuthentication(Req, State) ->
    case cowboy_req:parse_header(<<"authorization">>, Req) of
        {digest, Props} when is_list(Props) ->
            Realm = proplists:get_value(<<"realm">>, Props),
            Nonce = proplists:get_value(<<"nonce">>, Props),
            Method = cowboy_req:method(Req),
            RealUri = getDigestUri(Req), %% the authentication header has a property that describes the uri, but we don't trust the user
            Response = erlang:binary_to_list(proplists:get_value(<<"response">>, Props)),
            Opaque = erlang:binary_to_list(proplists:get_value(<<"opaque">>, Props)),
            Username = proplists:get_value(<<"username">>, Props),
            Password = getPasswordByUsername(Username),
            case digestHash(Username, Realm, Password, Method, RealUri, Nonce) of
                Response -> %%the result of the digestHash matches the "response" parameter that the user sent
                    Req1 = setDigestHeader(Req, Opaque),
                    {ok, Req1, State};
                _ ->
                    Req1 = setDigestHeader(Req, Opaque),
                    {stop, cowboy_req:reply(401, Req1)}
            end; 
	    _ ->
	        Req1 = setDigestHeader(Req, getRandomNonce()),
            {stop, cowboy_req:reply(401, Req1)}
            
    end.

getRandomNonce() ->
    toHex(rand:bytes(8)).

setDigestHeader(Req, Opaque) ->
    Nonce = getRandomNonce(),
    AuthenticateHeader =  erlang:list_to_binary(["digest realm=", $", ?REALM, $", ", nonce=", $", Nonce, $", ", opaque=", $", Opaque, $"]),
    cowboy_req:set_resp_header(<<"www-authenticate">>, AuthenticateHeader, Req).

getDigestUri(Req) ->
    Path = cowboy_req:path(Req),
    case cowboy_req:qs(Req) of
        <<>> ->
            Path;
        QueryString when is_binary(QueryString) ->
            <<Path/binary, $?, QueryString/binary>>
    end.

isPublic(_) ->
    false.

digestHash(_, _, unknown, _, _, _) -> unknown;
digestHash(Username, Realm, Password, Method, DigestUri, Nonce) -> 
    HA1 = toHex(erlang:md5([Username, ":", Realm, ":", Password])),
    HA2 = toHex(erlang:md5([Method, ":", DigestUri])),
    toHex(erlang:md5(([HA1, ":", Nonce, ":", HA2]))).

toHex(Bin) when is_binary(Bin) ->
    [hexChar(X) || <<X:4>> <= Bin].

hexChar(Num) when Num < 10 andalso Num >= 0-> 
    $0 + Num;
hexChar(Num) when Num < 16 -> 
    $a + Num - 10.

%TESTS

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

command_test_() ->
    [
        ?_assertEqual(
            "07c8d0952a0a91a921d74eba6f6007bb", digestHash(<<"phu">>, <<"cowboy">>, <<"qwe123">>, <<"GET">>, <<"/">>, <<"">>)),
        ?_assertEqual(
            "939e7578ed9e3c518a452acee763bce9", toHex(erlang:md5("Mufasa:testrealm@host.com:Circle Of Life")))
    ].

-endif.