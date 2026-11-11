defmodule AuthKit.GoogleOAuthTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth.Auth2
  alias AuthKit.OAuth.Google
  alias AuthKit.OAuth.IDToken
  alias AuthKit.Test.OAuthHTTPStub

  import ExUnit.CaptureLog

  @redirect_uri "http://localhost/auth/google/callback"

  setup_all do
    private = :public_key.generate_key({:rsa, 2048, 65537})
    other = :public_key.generate_key({:rsa, 2048, 65537})
    {:ok, private: private, other: other}
  end

  test "authorization URL sends an S256 challenge for the stored verifier" do
    assert {:ok, %{url: url, session_params: session}} =
             Google.authorize_url(client_id: "client", redirect_uri: @redirect_uri)

    query = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["code_challenge_method"] == "S256"
    assert query["code_challenge"] == s256(session.code_verifier)
    assert query["state"] == session.state
    assert query["nonce"] == session.nonce
    assert is_integer(session.issued_at)
  end

  test "callback rejects an expired state before the token request" do
    assert {:error, %{message: "OAuth state has expired"}} =
             Google.callback(
               [
                 client_id: "client",
                 client_secret: "secret",
                 redirect_uri: @redirect_uri,
                 session_params: %{
                   state: "state-1",
                   nonce: "nonce-1",
                   code_verifier: "verifier-1",
                   issued_at: System.system_time(:second) - 600
                 }
               ],
               %{"code" => "auth-code", "state" => "state-1"}
             )
  end

  test "callback rejects a session that has no code verifier" do
    assert {:error, %{message: "Missing code verifier"}} =
             Google.callback(
               [
                 client_id: "client",
                 client_secret: "secret",
                 redirect_uri: @redirect_uri,
                 session_params: %{
                   state: "state-1",
                   nonce: "nonce-1",
                   issued_at: System.system_time(:second)
                 }
               ],
               %{"code" => "auth-code", "state" => "state-1"}
             )
  end

  test "expired google state is the generic 401", %{conn: conn} do
    previous = Application.get_env(:auth_kit, :google)

    Application.put_env(:auth_kit, :google,
      client_id: "client",
      client_secret: "secret",
      redirect_uri: @redirect_uri
    )

    on_exit(fn ->
      if previous do
        Application.put_env(:auth_kit, :google, previous)
      else
        Application.delete_env(:auth_kit, :google)
      end
    end)

    log =
      capture_log(fn ->
        failed =
          conn
          |> put_session(:session_params, %{
            state: "state-1",
            nonce: "nonce-1",
            code_verifier: "verifier-1",
            issued_at: System.system_time(:second) - 600
          })
          |> Map.put(:query_string, "code=auth-code&state=state-1")
          |> Auth2.callback(%{
            "provider" => "google",
            "code" => "auth-code",
            "state" => "state-1"
          })

        send(self(), {:failed, failed.status, failed.resp_body})
      end)

    assert_received {:failed, 401, "OAuth sign-in failed"}
    assert log =~ "OAuth state has expired"
    refute log =~ "verifier-1"
  end

  test "accepts a token signed by the published RSA key", %{private: private} do
    jwk = jwk(private, "kid-1")
    %{url: url, count: count} = serve([[jwk]])
    jwt = sign(private, "kid-1", claims())

    assert {:ok, loaded} = IDToken.verify(jwt, url, "client", "nonce-1")
    assert loaded["email"] == "ada@example.com"
    assert loaded["sub"] == "sub-1"
    assert Agent.get(count, & &1) == 1

    assert {:ok, _} = IDToken.verify(jwt, url, "client", "nonce-1")
    assert Agent.get(count, & &1) == 1
  end

  test "accepts email_verified as the string true and the issuer without a scheme", %{
    private: private
  } do
    %{url: url} = serve([[jwk(private, "kid-1")]])

    jwt =
      sign(
        private,
        "kid-1",
        claims(%{"email_verified" => "true", "iss" => "accounts.google.com"})
      )

    assert {:ok, _} = IDToken.verify(jwt, url, "client", "nonce-1")
  end

  test "refetches a fresh cache once when the kid is unknown", %{private: private, other: other} do
    %{url: url, count: count, queue: queue} = serve([[jwk(other, "other")]])
    assert {:ok, _} = AuthKit.OAuth.JWKS.key(url, "other")
    assert Agent.get(count, & &1) == 1

    Agent.update(queue, fn _ -> [[jwk(private, "kid-1")]] end)
    jwt = sign(private, "kid-1", claims())

    assert {:ok, _} = IDToken.verify(jwt, url, "client", "nonce-1")
    assert Agent.get(count, & &1) == 2
  end

  test "stops after one refetch when the kid is still unknown", %{private: private, other: other} do
    %{url: url, count: count} = serve([[jwk(other, "other")], [jwk(other, "other")]])
    jwt = sign(private, "kid-1", claims())

    assert {:error, %{message: "Unknown ID token signing key"}} =
             IDToken.verify(jwt, url, "client", "nonce-1")

    assert Agent.get(count, & &1) == 2
  end

  test "refetches when max-age is zero", %{private: private} do
    %{url: url, count: count} =
      serve([[jwk(private, "kid-1")], [jwk(private, "kid-1")]], "max-age=0")

    jwt = sign(private, "kid-1", claims())
    assert {:ok, _} = IDToken.verify(jwt, url, "client", "nonce-1")
    assert {:ok, _} = IDToken.verify(jwt, url, "client", "nonce-1")
    assert Agent.get(count, & &1) == 2
  end

  test "rejects a bad signature, the wrong key, and failed claim checks", %{
    private: private,
    other: other
  } do
    %{url: url} = serve([[jwk(private, "kid-1")]])

    assert {:error, %{message: "Invalid ID token signature"}} =
             IDToken.verify(sign(other, "kid-1", claims()), url, "client", "nonce-1")

    bad_sig = sign(private, "kid-1", claims()) <> "x"

    assert {:error, %{message: "Invalid ID token signature"}} =
             IDToken.verify(bad_sig, url, "client", "nonce-1")

    assert {:error, %{message: "Invalid audience"}} =
             IDToken.verify(sign(private, "kid-1", claims()), url, "other-client", "nonce-1")

    assert {:error, %{message: "Invalid issuer"}} =
             IDToken.verify(
               sign(private, "kid-1", claims(%{"iss" => "https://evil.example"})),
               url,
               "client",
               "nonce-1"
             )

    assert {:error, %{message: "Invalid nonce"}} =
             IDToken.verify(sign(private, "kid-1", claims()), url, "client", "other-nonce")

    assert {:error, %{message: "ID token has expired"}} =
             IDToken.verify(
               sign(private, "kid-1", claims(%{"exp" => System.system_time(:second) - 5})),
               url,
               "client",
               "nonce-1"
             )

    assert {:error, %{message: "Email is not verified"}} =
             IDToken.verify(
               sign(private, "kid-1", claims(%{"email_verified" => false})),
               url,
               "client",
               "nonce-1"
             )
  end

  test "rejects alg none and a non-RS256 algorithm before fetching keys" do
    for alg <- ["none", "HS256", "RS384"] do
      header = Base.url_encode64(JSON.encode!(%{"alg" => alg, "kid" => "kid-1"}), padding: false)
      payload = Base.url_encode64(JSON.encode!(claims()), padding: false)
      jwt = header <> "." <> payload <> ".sig"

      assert {:error, %{message: "Invalid ID token"}} =
               IDToken.verify(jwt, "http://127.0.0.1:1/certs", "client", "nonce-1")
    end
  end

  test "rejects a mismatched azp", %{private: private} do
    %{url: url} = serve([[jwk(private, "kid-1")]])

    assert {:ok, _} =
             IDToken.verify(
               sign(private, "kid-1", claims(%{"azp" => "client"})),
               url,
               "client",
               "nonce-1"
             )

    assert {:error, %{message: "Invalid authorized party"}} =
             IDToken.verify(
               sign(private, "kid-1", claims(%{"azp" => "other-client"})),
               url,
               "client",
               "nonce-1"
             )
  end

  test "fails verification when the JWKS endpoint returns an error", %{private: private} do
    parent = self()

    stub =
      OAuthHTTPStub.start(fn _request ->
        send(parent, :jwks_fetch)
        OAuthHTTPStub.json(500, %{"error" => "unavailable"})
      end)

    on_exit(fn -> OAuthHTTPStub.stop(stub) end)

    jwt = sign(private, "kid-1", claims())
    url = stub.base <> "/certs/" <> Integer.to_string(System.unique_integer([:positive]))

    assert {:error, %{message: "JWKS request failed with status 500"}} =
             IDToken.verify(jwt, url, "client", "nonce-1")

    assert_received :jwks_fetch
  end

  defp serve(responses, cache_control \\ "public, max-age=3600, must-revalidate") do
    parent = self()
    {:ok, queue} = Agent.start_link(fn -> responses end)
    {:ok, count} = Agent.start_link(fn -> 0 end)

    stub =
      OAuthHTTPStub.start(fn _request ->
        send(parent, :jwks_fetch)

        Agent.update(count, &(&1 + 1))

        keys =
          Agent.get_and_update(queue, fn
            [next | rest] -> {next, rest}
            [] -> {[], []}
          end)

        OAuthHTTPStub.json(200, %{"keys" => keys}, [{"cache-control", cache_control}])
      end)

    on_exit(fn ->
      OAuthHTTPStub.stop(stub)
      if Process.alive?(queue), do: Agent.stop(queue)
      if Process.alive?(count), do: Agent.stop(count)
    end)

    %{
      url: stub.base <> "/certs/" <> Integer.to_string(System.unique_integer([:positive])),
      count: count,
      queue: queue
    }
  end

  defp claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => "https://accounts.google.com",
        "aud" => "client",
        "exp" => System.system_time(:second) + 3600,
        "nonce" => "nonce-1",
        "email" => "ada@example.com",
        "email_verified" => true,
        "sub" => "sub-1",
        "name" => "Ada"
      },
      overrides
    )
  end

  defp sign(private, kid, claims) do
    header =
      %{"alg" => "RS256", "typ" => "JWT", "kid" => kid}
      |> JSON.encode!()
      |> Base.url_encode64(padding: false)

    payload = claims |> JSON.encode!() |> Base.url_encode64(padding: false)
    signing_input = header <> "." <> payload

    signature =
      signing_input
      |> then(&:public_key.sign(&1, :sha256, private))
      |> Base.url_encode64(padding: false)

    signing_input <> "." <> signature
  end

  defp jwk(private, kid) do
    {:RSAPrivateKey, _version, n, e, _d, _p, _q, _dp, _dq, _qi, _other} = private

    %{
      "kty" => "RSA",
      "alg" => "RS256",
      "use" => "sig",
      "kid" => kid,
      "n" => Base.url_encode64(:binary.encode_unsigned(n), padding: false),
      "e" => Base.url_encode64(:binary.encode_unsigned(e), padding: false)
    }
  end

  defp s256(verifier) do
    :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)
  end
end
