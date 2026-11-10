defmodule AuthKit.GoogleOAuthTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth.Auth2
  alias AuthKit.Test.Identity
  alias AuthKit.Test.OAuthHTTPStub
  alias AuthKit.Test.User

  import ExUnit.CaptureLog

  @state "state-1"
  @code "auth-code"
  @redirect_uri "http://localhost/auth/google/callback"
  @access_token "ya29-do-not-log"

  test "a token response without an id token does not log the access token", %{conn: conn} do
    stub =
      stub(%{
        {"POST", "/token"} =>
          {200,
           %{
             "access_token" => @access_token,
             "error" => "invalid_grant",
             "error_description" => "Bad code"
           }}
      })

    put_google_config(stub)

    log =
      capture_log(fn ->
        failed =
          conn
          |> put_session(:session_params, %{state: @state, nonce: "nonce"})
          |> Map.put(:query_string, "code=#{@code}&state=#{@state}")
          |> Auth2.callback(%{"provider" => "google", "code" => @code, "state" => @state})

        send(self(), {:failed, failed.status, failed.resp_body})
      end)

    assert_received {:failed, 401, "OAuth sign-in failed"}
    assert log =~ "status=200"
    assert log =~ "error=invalid_grant"
    assert log =~ "error_description=Bad code"
    refute log =~ @access_token
    assert Repo.aggregate(User, :count) == 0
    assert Repo.aggregate(Identity, :count) == 0
  end

  defp put_google_config(stub) do
    previous = Application.get_env(:auth_kit, :google)

    Application.put_env(:auth_kit, :google,
      client_id: "client",
      client_secret: "secret",
      redirect_uri: @redirect_uri,
      token_url: stub.base <> "/token"
    )

    on_exit(fn ->
      if previous do
        Application.put_env(:auth_kit, :google, previous)
      else
        Application.delete_env(:auth_kit, :google)
      end
    end)
  end

  defp stub(responses) do
    parent = self()

    server =
      OAuthHTTPStub.start(fn request ->
        send(parent, {:oauth_http, request.method, request.path, request.headers, request.body})
        {status, body} = Map.fetch!(responses, {request.method, request.path})
        OAuthHTTPStub.json(status, body)
      end)

    on_exit(fn -> OAuthHTTPStub.stop(server) end)
    server
  end
end
