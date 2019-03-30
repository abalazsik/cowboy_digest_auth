-module(digest_middleware).

-export([execute/2]).

-behaviour(cowboy_middleware).

-define(USERNAME, "username").
-define(PASSWORD, "password").
-define(MAXNOONCE, 30000).

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
            case digestHash(getUsername(), Realm, getPassword(), Method, RealUri, Nonce) of
                Response -> 
                    Req1 = setDigestHeader(Req),
                    {ok, Req1, State};
                _ ->
                    Req1 = setDigestHeader(Req),
                    {stop, cowboy_req:reply(401, Req1)}
            end; 
	    _ ->
	        Req1 = setDigestHeader(Req),
            {stop, cowboy_req:reply(401, Req1)}
            
    end.

setDigestHeader(Req) ->
    Nonce = rand:uniform(?MAXNOONCE),
    Str = erlang:integer_to_list(Nonce, 16),
    Bin =  erlang:list_to_binary(["digest realm=\"cowboy\"  algorithm=\"MD5\" nonce=\"", Str, "\""]),
    cowboy_req:set_resp_header(<<"www-authenticate">>, Bin, Req).

getDigestUri(Req) ->
    A = cowboy_req:path(Req),
    case cowboy_req:qs(Req) of
        <<>> ->
            A;
        B when is_binary(B) ->
            <<A/binary, "?", B/binary>>
    end.

isPublic(_) ->
    false.

digestHash(Username, Realm, Password, Method, DigestUri, Nonce) -> 
    HA1 = toHex(erlang:md5([Username, ":", Realm, ":", Password])),
    HA2 = toHex(erlang:md5([Method, ":", DigestUri])),
    toHex(erlang:md5(([HA1, ":", Nonce, ":", HA2]))).

toHex(List) when is_binary(List) ->
    Hex = fun
            (X) when X < 16 -> "0" ++ erlang:integer_to_list(X,16);
            (X) -> erlang:integer_to_list(X,16)
        end,

    string:to_lower(lists:flatten([Hex(X) || <<X:8>> <= List])).

getUsername() ->
    ?USERNAME.

getPassword() ->
    ?PASSWORD.

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