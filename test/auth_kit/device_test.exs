defmodule AuthKit.DeviceTest do
  use AuthKit.ConnCase, async: false

  import Ecto.Query

  alias AuthKit.Auth
  alias AuthKit.Auth.Bearer
  alias AuthKit.Device
  alias AuthKit.Fixtures
  alias AuthKit.Tenants
  alias AuthKit.Test.TenantMember
  alias AuthKit.Test.UserToken

  @grant "urn:ietf:params:oauth:grant-type:device_code"
  @alphabet "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

  test "issue, pending poll, approve, then success returns a working api key", %{conn: conn} do
    user = Fixtures.user_fixture()

    assert {:ok, issued} =
             Auth.request_device_authorization(client_id: "demo-cli", scope: "openid profile")

    assert issued.expires_in == 1800
    assert issued.interval == 5
    assert issued.verification_uri == "/device"

    assert issued.verification_uri_complete ==
             "/device?user_code=#{URI.encode_www_form(issued.user_code)}"

    assert issued.user_code =~ ~r/^[#{@alphabet}]{4}-[#{@alphabet}]{4}$/
    refute issued.user_code =~ ~r/[01OI]/
    assert byte_size(issued.device_code) > 20

    row = device_row!(issued.device_code)
    canonical = String.replace(issued.user_code, "-", "")
    assert row.context == "device"
    assert row.status == "pending"
    assert is_nil(row.user_id)
    assert row.name == "demo-cli"
    assert row.sent_to == "openid profile"
    assert row.interval == 5
    assert row.token == :crypto.hash(:sha256, issued.device_code)
    assert row.user_code == :crypto.hash(:sha256, canonical)
    refute row.token == issued.device_code
    assert :binary.match(:erlang.term_to_binary(row), issued.device_code) == :nomatch
    assert :binary.match(:erlang.term_to_binary(row), issued.user_code) == :nomatch
    assert :binary.match(:erlang.term_to_binary(row), canonical) == :nomatch

    assert Device.code_body({:ok, issued})["device_code"] == issued.device_code
    assert Device.code_body({:ok, issued})["interval"] == 5

    assert {:ok, view} = Auth.get_device_authorization(user, issued.user_code)
    assert view.status == "pending"
    assert view.client_id == "demo-cli"
    assert view.scope == "openid profile"

    approval = Device.approval_body({:ok, view})
    assert approval["status"] == "pending"
    assert approval["client_id"] == "demo-cli"
    assert approval["scope"] == "openid profile"
    assert Device.approval_body({:error, :invalid_grant})["error"] == "invalid_grant"

    assert {:error, :authorization_pending} = poll(issued.device_code)

    messy = issued.user_code |> String.downcase() |> String.replace("-", " ")
    assert {:ok, approved} = Auth.approve_device_authorization(user, messy)
    assert approved.status == "approved"
    assert approved.client_id == "demo-cli"
    assert approved.user_id == user.id

    assert {:ok, token} = poll(issued.device_code)
    assert token.token_type == "Bearer"
    assert is_binary(token.access_token)
    assert token.scope == "openid profile"
    assert is_nil(token.expires_in)
    assert token.api_key_id

    body = Device.token_body({:ok, token})
    assert body["access_token"] == token.access_token
    assert body["token_type"] == "Bearer"
    refute Map.has_key?(body, "expires_in")
    assert body["scope"] == "openid profile"
    refute Map.has_key?(body, "api_key_id")

    assert %{valid: true, error: nil, key: meta} = Auth.verify_api_key(token.access_token)
    assert meta.id == token.api_key_id
    assert meta.user_id == user.id
    assert meta.name == "demo-cli"
    refute Map.has_key?(meta, :key)

    headers = Device.credential_headers(token)

    authed =
      conn
      |> put_req_header("authorization", headers["authorization"])
      |> Bearer.call([])

    assert authed.assigns.current_user.id == user.id
    assert authed.assigns.current_api_key.id == token.api_key_id
    refute Map.has_key?(authed.assigns.current_api_key, :key)

    via_header =
      :get
      |> Plug.Test.conn("/")
      |> Map.replace!(:secret_key_base, String.duplicate("a", 64))
      |> Plug.Test.init_test_session(%{})
      |> put_req_header("x-api-key", headers["x-api-key"])
      |> Bearer.call([])

    assert via_header.assigns.current_user.id == user.id
    assert via_header.assigns.current_api_key.id == token.api_key_id

    key_row = Repo.get!(UserToken, token.api_key_id)
    assert key_row.context == "api"
    assert key_row.token == :crypto.hash(:sha256, token.access_token)
    assert :binary.match(:erlang.term_to_binary(key_row), token.access_token) == :nomatch

    assert {:ok, %{api_keys: keys}} = Auth.list_api_keys(user)
    assert Enum.any?(keys, &(&1.id == token.api_key_id))

    assert {:error, :invalid_grant} = poll(issued.device_code)
    refute device_row(issued.device_code)

    assert {:ok, %{success: true}} = Auth.revoke_api_key(user, token.api_key_id)

    assert %{valid: false, error: %{code: "INVALID_API_KEY"}} =
             Auth.verify_api_key(token.access_token)
  end

  test "denial returns access_denied" do
    user = Fixtures.user_fixture()
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

    assert {:ok, %{status: "denied"}} =
             Auth.deny_device_authorization(user, " " <> String.downcase(issued.user_code))

    assert {:error, :access_denied} = poll(issued.device_code)
    assert {:error, :access_denied} = Auth.approve_device_authorization(user, issued.user_code)

    assert Device.token_body({:error, :access_denied}) == %{
             "error" => "access_denied",
             "error_description" => Device.error_description(:access_denied)
           }
  end

  test "an expired device code returns expired_token" do
    user = Fixtures.user_fixture()
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")
    expire!(issued.device_code)

    assert {:error, :expired_token} = poll(issued.device_code)
    refute device_row(issued.device_code)

    {:ok, other} = Auth.request_device_authorization(client_id: "demo-cli")
    expire!(other.device_code)

    assert {:error, :expired_token} = Auth.approve_device_authorization(user, other.user_code)
    refute device_row(other.device_code)
  end

  test "polling faster than the interval returns slow_down" do
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

    assert {:error, :authorization_pending} = poll(issued.device_code)
    assert {:error, :slow_down} = poll(issued.device_code)
    assert device_row!(issued.device_code).interval == 10

    assert Device.token_body({:error, :slow_down})["error"] == "slow_down"

    past = DateTime.add(DateTime.utc_now(), -30, :second)

    {1, _} =
      from(t in UserToken, where: t.id == ^device_row!(issued.device_code).id)
      |> Repo.update_all(set: [last_request: past])

    assert {:error, :authorization_pending} = poll(issued.device_code)
    assert device_row!(issued.device_code).interval == 10
  end

  test "concurrent polls of an expired code do not raise" do
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")
    row = device_row!(issued.device_code)
    expire!(issued.device_code)

    results = parallel_polls(issued.device_code, 8)

    assert Enum.all?(results, fn
             {:error, reason} -> reason in [:expired_token, :invalid_grant]
             other -> flunk("unexpected poll result #{inspect(other)}")
           end)

    assert Enum.any?(results, &match?({:error, :expired_token}, &1))
    refute Repo.get(UserToken, row.id)
  end

  test "concurrent fast polls return slow_down and do not raise" do
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")
    assert {:error, :authorization_pending} = poll(issued.device_code)

    results = parallel_polls(issued.device_code, 8)

    assert Enum.all?(results, &(&1 == {:error, :slow_down}))
    interval = device_row!(issued.device_code).interval
    assert interval > 5
    assert interval <= 5 + 8 * 5
  end

  test "a mismatched client id does not consume the code" do
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

    assert {:error, :invalid_grant} =
             Auth.poll_device_token(issued.device_code,
               grant_type: @grant,
               client_id: "other-cli"
             )

    assert {:error, :authorization_pending} = poll(issued.device_code)
    assert device_row!(issued.device_code).status == "pending"
  end

  test "unknown codes and disallowed clients are rejected" do
    user = Fixtures.user_fixture()

    assert {:error, :invalid_request} = Auth.request_device_authorization([])
    assert {:error, :invalid_request} = Auth.request_device_authorization(client_id: "")
    assert {:error, :invalid_grant} = Auth.approve_device_authorization(user, "ABCD-EFGH")

    assert {:error, :invalid_user} =
             Auth.request_device_authorization(
               client_id: "demo-cli",
               user_id: Ecto.UUID.generate()
             )

    with_device_config([allowed_clients: ["puppi"]], fn ->
      assert {:error, :invalid_client} = Auth.request_device_authorization(client_id: "other")
      assert {:ok, _} = Auth.request_device_authorization(client_id: "puppi")
    end)

    with_device_config([allowed_clients: fn id -> id == "only" end], fn ->
      assert {:error, :invalid_client} = Auth.request_device_authorization(client_id: "puppi")
      assert {:ok, _} = Auth.request_device_authorization(client_id: "only")
    end)
  end

  test "only the pre-bound user can approve" do
    owner = Fixtures.user_fixture()
    other = Fixtures.user_fixture()

    assert {:ok, issued} =
             Auth.request_device_authorization(client_id: "demo-cli", user_id: owner.id)

    assert device_row!(issued.device_code).user_id == owner.id
    assert device_row!(issued.device_code).status == "pending"
    assert {:error, :access_denied} = Auth.get_device_authorization(other, issued.user_code)
    assert {:error, :access_denied} = Auth.approve_device_authorization(other, issued.user_code)
    assert {:error, :access_denied} = Auth.deny_device_authorization(other, issued.user_code)

    assert {:ok, %{status: "approved"}} =
             Auth.approve_device_authorization(owner, issued.user_code)

    assert {:ok, token} = poll(issued.device_code)
    assert Auth.verify_api_key(token.access_token).key.user_id == owner.id
  end

  test "approval can scope the issued key to the active tenant", %{conn: conn} do
    user = Fixtures.user_fixture()
    outsider = Fixtures.user_fixture()
    slug = "device-#{System.unique_integer([:positive])}"
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(user, %{name: "Device", slug: slug})

    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

    assert {:error, :not_a_member} =
             Auth.approve_device_authorization(outsider, issued.user_code, tenant_id: tenant.id)

    assert device_row!(issued.device_code).status == "pending"

    assert {:ok, approved} =
             Auth.approve_device_authorization(user, issued.user_code, tenant_id: tenant.id)

    assert approved.active_tenant_id == tenant.id
    assert device_row!(issued.device_code).tenant_scoped == true

    assert {:ok, token} = poll(issued.device_code)

    authed =
      conn
      |> put_req_header("x-api-key", token.access_token)
      |> Bearer.call([])

    assert authed.assigns.current_user.id == user.id
    assert authed.assigns.current_tenant_id == tenant.id
    assert authed.assigns.current_api_key.tenant_scoped == true
  end

  test "deny-after-approve cancels the grant so no key is issued" do
    user = Fixtures.user_fixture()
    other = Fixtures.user_fixture()
    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

    assert {:ok, %{status: "approved"}} =
             Auth.approve_device_authorization(user, issued.user_code)

    assert {:error, :access_denied} = Auth.deny_device_authorization(other, issued.user_code)
    assert device_row!(issued.device_code).status == "approved"

    assert {:ok, %{status: "denied"}} = Auth.deny_device_authorization(user, issued.user_code)
    assert device_row!(issued.device_code).status == "denied"

    assert {:error, :access_denied} = poll(issued.device_code)
    assert {:error, :access_denied} = poll(issued.device_code)
    assert {:ok, %{api_keys: [], total: 0}} = Auth.list_api_keys(user)
  end

  test "member-removed-then-readded does not mint a key" do
    owner = Fixtures.user_fixture()
    user = Fixtures.user_fixture()
    slug = "device-gap-#{System.unique_integer([:positive])}"
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Gap", slug: slug})

    assert {:ok, _member} =
             Tenants.add_member(owner, tenant, %{user_id: user.id, role: ["member"]})

    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

    assert {:ok, _} =
             Auth.approve_device_authorization(user, issued.user_code, tenant_id: tenant.id)

    member = Repo.get_by!(TenantMember, user_id: user.id, tenant_id: tenant.id)
    Repo.delete!(member)

    assert {:error, :access_denied} = poll(issued.device_code)
    refute device_row(issued.device_code)
    assert {:ok, %{api_keys: [], total: 0}} = Auth.list_api_keys(user)

    assert {:ok, _member} =
             Tenants.add_member(owner, tenant, %{user_id: user.id, role: ["member"]})

    assert {:error, :invalid_grant} = poll(issued.device_code)
    assert {:ok, %{api_keys: [], total: 0}} = Auth.list_api_keys(user)
  end

  test "user code attempts lock out after the budget is exhausted" do
    user = Fixtures.user_fixture()

    assert Device.max_user_code_attempts() == 128

    with_device_config([user_code_length: 7], fn ->
      assert Device.max_user_code_attempts() == 4
      {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

      assert {:ok, %{status: "pending"}} =
               Auth.get_device_authorization(user, issued.user_code)

      for _ <- 1..4 do
        assert {:error, :invalid_grant} = Auth.get_device_authorization(user, "AAAAAAA")
      end

      assert {:error, :too_many_attempts} =
               Auth.get_device_authorization(user, issued.user_code)

      assert {:error, :too_many_attempts} =
               Auth.approve_device_authorization(user, issued.user_code)

      assert {:error, :too_many_attempts} =
               Auth.deny_device_authorization(user, issued.user_code)

      assert device_row!(issued.device_code).status == "pending"
      assert {:error, :authorization_pending} = poll(issued.device_code)

      assert Device.error_body(:too_many_attempts)["error"] == "too_many_attempts"

      past = DateTime.add(DateTime.utc_now(), -5, :second)

      {1, _} =
        from(t in UserToken, where: t.context == "device_attempt")
        |> Repo.update_all(set: [expires_at: past])

      assert {:ok, %{status: "pending"}} =
               Auth.get_device_authorization(user, issued.user_code)
    end)
  end

  test "concurrent user-code misses do not exceed the attempt budget" do
    user = Fixtures.user_fixture()

    with_device_config([user_code_length: 7], fn ->
      limit = Device.max_user_code_attempts()
      {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")

      results =
        1..12
        |> Task.async_stream(
          fn _ -> Auth.get_device_authorization(user, "AAAAAAA") end,
          max_concurrency: 12,
          timeout: 15_000
        )
        |> Enum.map(fn
          {:ok, result} -> result
          {:exit, reason} -> flunk("lookup raised: #{inspect(reason)}")
        end)

      misses = Enum.count(results, &(&1 == {:error, :invalid_grant}))
      lockouts = Enum.count(results, &(&1 == {:error, :too_many_attempts}))

      assert misses <= limit
      assert misses + lockouts == 12
      assert lockouts >= 1

      assert {:error, :too_many_attempts} =
               Auth.approve_device_authorization(user, issued.user_code)

      assert device_row!(issued.device_code).status == "pending"
    end)
  end

  test "a 300-character scope is invalid_request" do
    assert {:error, :invalid_request} =
             Auth.request_device_authorization(
               client_id: "demo-cli",
               scope: String.duplicate("a", 300)
             )

    assert {:error, :invalid_request} =
             Auth.request_device_authorization(
               client_id: "demo-cli",
               scope: String.duplicate("b", 256)
             )

    scope = String.duplicate("c", 255)

    assert {:ok, issued} =
             Auth.request_device_authorization(client_id: "demo-cli", scope: scope)

    assert device_row!(issued.device_code).sent_to == scope
  end

  test "verification_uri_complete keeps user_code in the query, not the fragment" do
    with_device_config([verification_uri: "https://example.com/device#approve"], fn ->
      {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")
      uri = URI.parse(issued.verification_uri_complete)

      assert uri.fragment == "approve"
      assert uri.query == "user_code=#{URI.encode_www_form(issued.user_code)}"
      refute issued.verification_uri_complete =~ ~r/#.*user_code/
    end)

    with_device_config([verification_uri: "/device?from=cli#approve"], fn ->
      {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")
      uri = URI.parse(issued.verification_uri_complete)

      assert uri.fragment == "approve"

      assert uri.query ==
               "from=cli&user_code=#{URI.encode_www_form(issued.user_code)}"
    end)
  end

  test "a bad device api key setting fails at request time and a later change ends the grant" do
    user = Fixtures.user_fixture()

    with_device_config([api_key_name: String.duplicate("n", 40)], fn ->
      assert {:error, :server_error} = Auth.request_device_authorization(client_id: "demo-cli")
    end)

    with_device_config([api_key_prefix: "no pe"], fn ->
      assert {:error, :server_error} = Auth.request_device_authorization(client_id: "demo-cli")
    end)

    with_device_config([api_key_expires_in: 60], fn ->
      assert {:error, :server_error} = Auth.request_device_authorization(client_id: "demo-cli")
    end)

    {:ok, issued} = Auth.request_device_authorization(client_id: "demo-cli")
    assert {:ok, _} = Auth.approve_device_authorization(user, issued.user_code)

    with_device_config([api_key_name: String.duplicate("n", 40)], fn ->
      assert {:error, :server_error} = poll(issued.device_code)
      refute device_row(issued.device_code)
      assert {:error, :invalid_grant} = poll(issued.device_code)
    end)

    assert {:ok, %{api_keys: [], total: 0}} = Auth.list_api_keys(user)
  end

  defp poll(device_code) do
    Auth.poll_device_token(device_code, grant_type: @grant, client_id: "demo-cli")
  end

  defp device_row(device_code) do
    hashed = :crypto.hash(:sha256, device_code)
    Repo.get_by(UserToken, context: "device", token: hashed)
  end

  defp device_row!(device_code) do
    device_row(device_code) || flunk("device grant missing")
  end

  defp expire!(device_code) do
    row = device_row!(device_code)
    past = DateTime.add(DateTime.utc_now(), -5, :second)

    {1, _} =
      from(t in UserToken, where: t.id == ^row.id)
      |> Repo.update_all(set: [expires_at: past])
  end

  defp parallel_polls(device_code, count) do
    1..count
    |> Task.async_stream(
      fn _ ->
        Auth.poll_device_token(device_code, grant_type: @grant, client_id: "demo-cli")
      end,
      max_concurrency: count,
      timeout: 15_000
    )
    |> Enum.map(fn
      {:ok, result} -> result
      {:exit, reason} -> flunk("poll raised: #{inspect(reason)}")
    end)
  end

  defp with_device_config(config, fun) do
    previous = Application.get_env(:auth_kit, :device_authorization)
    Application.put_env(:auth_kit, :device_authorization, config)

    try do
      fun.()
    after
      if previous do
        Application.put_env(:auth_kit, :device_authorization, previous)
      else
        Application.delete_env(:auth_kit, :device_authorization)
      end
    end
  end
end
