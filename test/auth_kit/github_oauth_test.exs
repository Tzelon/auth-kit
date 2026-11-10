defmodule AuthKit.GitHubOAuthTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.Auth2
  alias AuthKit.Fixtures
  alias AuthKit.OAuth.GitHub
  alias AuthKit.Test.Identity
  alias AuthKit.Test.OAuthHTTPStub
  alias AuthKit.Test.User

  @state "state-1"
  @code "auth-code"
  @redirect_uri "http://localhost/auth/github/callback"

  test "authorization URL requests user:email" do
    assert {:ok, %{url: url, session_params: %{state: state}}} =
             GitHub.authorize_url(
               client_id: "client",
               redirect_uri: @redirect_uri
             )

    uri = URI.parse(url)
    assert uri.scheme == "https"
    assert uri.host == "github.com"
    assert uri.path == "/login/oauth/authorize"
    query = URI.decode_query(uri.query)
    assert query["client_id"] == "client"
    assert query["redirect_uri"] == @redirect_uri
    assert query["response_type"] == "code"
    assert query["state"] == state
    assert query["scope"] |> String.split(" ") |> Enum.sort() == ["read:user", "user:email"]
  end

  test "signs in with the primary verified email", %{conn: conn} do
    stub =
      stub(%{
        {"POST", "/login/oauth/access_token"} =>
          {200,
           %{
             "access_token" => "gho_test",
             "token_type" => "bearer",
             "scope" => "read:user,user:email"
           }},
        {"GET", "/user"} =>
          {200,
           %{
             "id" => 42,
             "login" => "ada",
             "name" => "Ada Lovelace",
             "email" => "42+ada@users.noreply.github.com",
             "avatar_url" => "https://example.com/ada.png"
           }},
        {"GET", "/user/emails"} =>
          {200,
           [
             %{
               "email" => "42+ada@users.noreply.github.com",
               "primary" => false,
               "verified" => true
             },
             %{"email" => "ada@example.com", "primary" => true, "verified" => true}
           ]}
      })

    put_github_config(stub)

    conn =
      conn
      |> callback_conn()
      |> Auth2.callback(%{"provider" => "github", "code" => @code, "state" => @state},
        auto_signup: true
      )

    assert redirected_to(conn) == "/"
    user = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert user.email == "ada@example.com"
    assert user.name == "Ada Lovelace"
    assert user.avatar_url == "https://example.com/ada.png"
    assert user.email_confirmed_at

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "github")
    assert identity.identity == "42"
    assert identity.access_token == "gho_test"
    assert identity.scope == "read:user,user:email"

    assert_received {:oauth_http, "POST", "/login/oauth/access_token", _headers, body}

    assert %{
             "grant_type" => "authorization_code",
             "code" => @code,
             "client_id" => "client",
             "client_secret" => "secret",
             "redirect_uri" => @redirect_uri
           } = URI.decode_query(body)

    assert_received {:oauth_http, "GET", "/user", user_headers, ""}
    assert user_headers["authorization"] == "Bearer gho_test"
    assert user_headers["user-agent"] == "auth-kit"
    assert_received {:oauth_http, "GET", "/user/emails", email_headers, ""}
    assert email_headers["authorization"] == "Bearer gho_test"
  end

  test "refuses sign-in when no email is primary and verified", %{conn: conn} do
    stub =
      stub(%{
        {"POST", "/login/oauth/access_token"} => {200, %{"access_token" => "gho_test"}},
        {"GET", "/user"} =>
          {200, %{"id" => 7, "login" => "ada", "email" => "ada@example.com", "name" => "Ada"}},
        {"GET", "/user/emails"} =>
          {200, [%{"email" => "ada@example.com", "primary" => false, "verified" => true}]}
      })

    put_github_config(stub)

    assert_raise AuthKit.OAuth.Error, "GitHub account has no primary verified email", fn ->
      conn
      |> callback_conn()
      |> Auth2.callback(%{"provider" => "github", "code" => @code, "state" => @state})
    end

    assert Repo.aggregate(User, :count) == 0
    assert Repo.aggregate(Identity, :count) == 0
  end

  test "refuses sign-in when the primary email is unverified", %{conn: conn} do
    stub =
      stub(%{
        {"POST", "/login/oauth/access_token"} => {200, %{"access_token" => "gho_test"}},
        {"GET", "/user"} =>
          {200, %{"id" => 7, "login" => "ada", "email" => "other@example.com", "name" => "Ada"}},
        {"GET", "/user/emails"} =>
          {200,
           [
             %{"email" => "ada@example.com", "primary" => true, "verified" => false},
             %{"email" => "other@example.com", "primary" => false, "verified" => true}
           ]}
      })

    put_github_config(stub)

    assert_raise AuthKit.OAuth.Error, "Email is not verified", fn ->
      conn
      |> callback_conn()
      |> Auth2.callback(%{"provider" => "github", "code" => @code, "state" => @state})
    end

    assert Repo.aggregate(User, :count) == 0
    assert Repo.aggregate(Identity, :count) == 0
  end

  test "refuses sign-in when the token exchange fails", %{conn: conn} do
    stub =
      stub(%{
        {"POST", "/login/oauth/access_token"} =>
          {400,
           %{
             "error" => "bad_verification_code",
             "error_description" => "The code passed is incorrect or expired."
           }}
      })

    put_github_config(stub)

    assert_raise AuthKit.OAuth.Error, ~r/^Token request failed with status 400:/, fn ->
      conn
      |> callback_conn()
      |> Auth2.callback(%{"provider" => "github", "code" => @code, "state" => @state})
    end

    assert Repo.aggregate(User, :count) == 0
  end

  test "links a verified GitHub email to the existing user", %{conn: conn} do
    {existing, _password} = Fixtures.user_with_password_fixture(%{email: "ada@example.com"})

    stub =
      stub(%{
        {"POST", "/login/oauth/access_token"} => {200, %{"access_token" => "gho_link"}},
        {"GET", "/user"} =>
          {200, %{"id" => 42, "login" => "ada", "name" => "Ada", "email" => nil}},
        {"GET", "/user/emails"} =>
          {200, [%{"email" => "Ada@Example.com", "primary" => true, "verified" => true}]}
      })

    put_github_config(stub)

    conn =
      conn
      |> callback_conn()
      |> Auth2.callback(%{"provider" => "github", "code" => @code, "state" => @state})

    user = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert user.id == existing.id
    assert user.email == "ada@example.com"
    assert user.email_confirmed_at
    refute Repo.get_by(Identity, user_id: user.id, provider: "credential")

    identity = Repo.get_by!(Identity, provider: "github", identity: "42")
    assert identity.user_id == existing.id
    assert identity.access_token == "gho_link"
    assert Repo.aggregate(User, :count) == 1
  end

  defp callback_conn(conn) do
    conn
    |> put_session(:session_params, %{state: @state})
    |> Map.put(:query_string, "code=#{@code}&state=#{@state}")
  end

  defp put_github_config(stub) do
    previous = Application.get_env(:auth_kit, :github)

    Application.put_env(:auth_kit, :github,
      client_id: "client",
      client_secret: "secret",
      redirect_uri: @redirect_uri,
      token_url: stub.base <> "/login/oauth/access_token",
      user_url: stub.base <> "/user",
      emails_url: stub.base <> "/user/emails"
    )

    on_exit(fn ->
      if previous do
        Application.put_env(:auth_kit, :github, previous)
      else
        Application.delete_env(:auth_kit, :github)
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
