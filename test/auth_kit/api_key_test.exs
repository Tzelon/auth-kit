defmodule AuthKit.ApiKeyTest do
  use AuthKit.ConnCase, async: false

  import Ecto.Query

  alias AuthKit.ApiKey
  alias AuthKit.Auth
  alias AuthKit.Auth.Bearer
  alias AuthKit.Fixtures
  alias AuthKit.Tenants
  alias AuthKit.Test.UserToken
  alias AuthKit.UserToken, as: Tokens

  test "create stores the hash and returns the plaintext once", %{conn: conn} do
    user = Fixtures.user_fixture()

    assert {:ok, api_key} =
             Auth.create_api_key(user,
               name: "ci",
               prefix: "pup_",
               permissions: %{files: ["read"]}
             )

    assert String.starts_with?(api_key.key, "pup_")
    assert String.length(api_key.key) == byte_size("pup_") + 64
    assert api_key.prefix == "pup_"
    assert api_key.start == String.slice(api_key.key, 0, 6)
    assert api_key.name == "ci"
    assert api_key.reference_id == user.id
    assert api_key.user_id == user.id
    assert api_key.config_id == "default"
    assert api_key.enabled
    assert is_nil(api_key.expires_at)
    assert is_nil(api_key.last_request)
    assert api_key.permissions == %{"files" => ["read"]}
    assert api_key.created_at
    assert api_key.updated_at

    row = Repo.get!(UserToken, api_key.id)
    assert row.context == "api"
    assert row.token == :crypto.hash(:sha256, api_key.key)
    assert :binary.match(:erlang.term_to_binary(row), api_key.key) == :nomatch

    assert %{valid: true, error: nil, key: verified} = Auth.verify_api_key(api_key.key)
    refute Map.has_key?(verified, :key)
    assert verified.id == api_key.id
    assert verified.last_request
    assert verified.permissions == %{"files" => ["read"]}

    assert %{valid: false, error: %{code: "INVALID_API_KEY"}, key: nil} =
             Auth.verify_api_key("pup_nope")

    authed =
      conn
      |> put_req_header("authorization", "Bearer " <> api_key.key)
      |> Bearer.call([])

    assert authed.assigns.current_user.id == user.id
    assert authed.assigns.current_api_key.id == api_key.id
    refute Map.has_key?(authed.assigns.current_api_key, :key)
    assert is_nil(authed.assigns.current_tenant_id)
  end

  test "list returns metadata without the secret, and revoke removes one key" do
    user = Fixtures.user_fixture()
    other = Fixtures.user_fixture()
    session = Auth.generate_session_token(user)
    session_row = Repo.get_by!(UserToken, token: session, context: "session")

    assert {:ok, first} = Auth.create_api_key(user, name: "a", prefix: "pup_")
    assert {:ok, second} = Auth.create_api_key(user, name: "b", prefix: "pup_")
    assert {:ok, _other} = Auth.create_api_key(other, name: "c", prefix: "pup_")

    assert {:ok, %{api_keys: keys, total: 2, limit: nil, offset: 0}} = Auth.list_api_keys(user)

    assert Enum.map(keys, & &1.name) |> Enum.sort() == ["a", "b"]

    for key <- keys do
      refute Map.has_key?(key, :key)
      refute Map.has_key?(key, :token)
      assert key.user_id == user.id
      assert key.prefix == "pup_"
      assert key.start
      assert key.created_at
      assert is_nil(key.expires_at)
    end

    assert {:ok, fetched} = Auth.get_api_key(user, first.id)
    refute Map.has_key?(fetched, :key)
    assert fetched.name == "a"
    assert {:error, :not_found} = Auth.get_api_key(other, first.id)
    assert {:error, :not_found} = Auth.revoke_api_key(other, first.id)
    assert {:error, :not_found} = Auth.revoke_api_key(user, session_row.id)
    assert {:error, :not_found} = Auth.revoke_api_key(user, "nope")

    assert {:ok, %{success: true}} = Auth.revoke_api_key(user, first.id)
    assert %{valid: false, error: %{code: "INVALID_API_KEY"}} = Auth.verify_api_key(first.key)
    assert %{valid: true, key: _} = Auth.verify_api_key(second.key)
    assert Auth.fetch_user_by_session_token(session).id == user.id
    assert {:error, :not_found} = Auth.delete_api_key(user, first.id)

    assert {:ok, %{api_keys: [listed], total: 1}} =
             Auth.list_api_keys(user, sort_by: "name", sort_direction: "asc")

    assert listed.id == second.id
  end

  test "a session bearer still wins over the api key fallback", %{conn: conn} do
    user = Fixtures.user_fixture()
    token = Auth.generate_session_token(user)
    encoded = Tokens.encode_session_token(token)

    authed =
      conn
      |> put_req_header("authorization", "Bearer " <> encoded)
      |> Bearer.call([])

    assert authed.assigns.current_user.id == user.id
    assert authed.assigns.current_api_key == nil
    assert authed.assigns.current_tenant_id == nil
  end

  test "x-api-key authenticates and does not fall through to a bearer session" do
    user = Fixtures.user_fixture()
    {:ok, api_key} = Auth.create_api_key(user, name: "header", prefix: "pup_")
    encoded = user |> Auth.generate_session_token() |> Tokens.encode_session_token()

    authed =
      build_conn()
      |> put_req_header("x-api-key", api_key.key)
      |> Bearer.call([])

    assert authed.assigns.current_user.id == user.id
    assert authed.assigns.current_api_key.id == api_key.id

    blocked =
      build_conn()
      |> put_req_header("x-api-key", "missing")
      |> put_req_header("authorization", "Bearer " <> encoded)
      |> Bearer.call([])

    assert blocked.assigns.current_user == nil
  end

  test "expiry, disable, remaining, and permissions follow the key" do
    user = Fixtures.user_fixture()

    assert {:error, :expires_in_too_small} = Auth.create_api_key(user, expires_in: 60)
    assert {:error, :expires_in_too_large} = Auth.create_api_key(user, expires_in: 366 * 86_400)
    assert {:error, :invalid_prefix} = Auth.create_api_key(user, prefix: "no pe")
    assert {:error, :invalid_name_length} = Auth.create_api_key(user, name: "")

    assert {:error, {:not_supported, :rate_limit_max}} =
             Auth.create_api_key(user, rate_limit_max: 10)

    assert {:error, :metadata_disabled} = Auth.create_api_key(user, metadata: %{env: "ci"})

    assert {:ok, lasting} = Auth.create_api_key(user, name: "lasting")
    assert is_nil(lasting.expires_at)
    assert %{valid: true} = Auth.verify_api_key(lasting.key)

    assert {:ok, expiring} = Auth.create_api_key(user, name: "expiring", expires_in: 86_400)
    past = DateTime.utc_now() |> DateTime.add(-1, :minute)
    Repo.update_all(from(t in UserToken, where: t.id == ^expiring.id), set: [expires_at: past])

    assert %{valid: false, error: %{code: "KEY_EXPIRED"}} = Auth.verify_api_key(expiring.key)
    refute Repo.get(UserToken, expiring.id)

    assert {:ok, limited} = Auth.create_api_key(user, name: "once", remaining: 1)
    assert %{valid: true, key: %{remaining: 0}} = Auth.verify_api_key(limited.key)
    assert %{valid: false, error: %{code: "USAGE_EXCEEDED"}} = Auth.verify_api_key(limited.key)
    refute Repo.get(UserToken, limited.id)

    assert {:ok, gated} =
             Auth.create_api_key(user, name: "gated", permissions: %{files: ["read"]})

    assert %{valid: true} = Auth.verify_api_key(gated.key, permissions: %{"files" => ["read"]})

    assert %{valid: false, error: %{code: "KEY_NOT_FOUND"}} =
             Auth.verify_api_key(gated.key, permissions: %{files: ["write"]})

    assert %{valid: true} = Auth.verify_api_key(gated.key)
    assert Repo.get(UserToken, gated.id)

    assert {:ok, renamed} = Auth.update_api_key(user, gated.id, name: "renamed", enabled: false)
    assert renamed.name == "renamed"
    assert renamed.enabled == false
    refute Map.has_key?(renamed, :key)
    assert %{valid: false, error: %{code: "KEY_DISABLED"}} = Auth.verify_api_key(gated.key)
    assert Repo.get(UserToken, gated.id)

    assert {:error, :no_values_to_update} = Auth.update_api_key(user, gated.id, [])
    assert {:ok, cleared} = Auth.update_api_key(user, lasting.id, expires_in: nil)
    assert is_nil(cleared.expires_at)
  end

  test "delete_all_expired_api_keys removes expired api keys only" do
    user = Fixtures.user_fixture()
    session = Auth.generate_session_token(user)
    assert {:ok, live} = Auth.create_api_key(user, name: "live")
    assert {:ok, dead} = Auth.create_api_key(user, name: "dead", expires_in: 86_400)

    past = DateTime.utc_now() |> DateTime.add(-1, :minute)
    Repo.update_all(from(t in UserToken, where: t.id == ^dead.id), set: [expires_at: past])

    assert {:ok, 1} = ApiKey.delete_all_expired_api_keys(force: true)
    refute Repo.get(UserToken, dead.id)
    assert Repo.get(UserToken, live.id)
    assert Auth.fetch_user_by_session_token(session).id == user.id
    assert {:ok, 0} = Auth.delete_all_expired_api_keys()
  end

  test "list paginates and filters by config id" do
    user = Fixtures.user_fixture()

    for name <- ["a", "b", "c"] do
      assert {:ok, _} = Auth.create_api_key(user, name: name, config_id: "ci")
    end

    assert {:ok, _} = Auth.create_api_key(user, name: "other", config_id: "public")

    assert {:ok, %{api_keys: page, total: 3, limit: 1, offset: 1}} =
             Auth.list_api_keys(user,
               config_id: "ci",
               limit: 1,
               offset: 1,
               sort_by: "name",
               sort_direction: "asc"
             )

    assert Enum.map(page, & &1.name) == ["b"]

    assert {:ok, created} = Auth.create_api_key(user, name: "scoped", config_id: "ci")
    assert %{valid: false} = Auth.verify_api_key(created.key, config_id: "public")
    assert %{valid: true} = Auth.verify_api_key(created.key, config_id: "ci")
    assert %{valid: true} = Auth.verify_api_key(created.key)
  end

  test "config covers prefix, metadata, name, and default expiry" do
    user = Fixtures.user_fixture()

    with_api_key_config([default_prefix: "ak_"], fn ->
      assert {:ok, api_key} = Auth.create_api_key(user, name: "pref")
      assert String.starts_with?(api_key.key, "ak_")
      assert api_key.prefix == "ak_"
    end)

    with_api_key_config([require_name: true], fn ->
      assert {:error, :name_required} = Auth.create_api_key(user, [])
    end)

    with_api_key_config([enable_metadata: true], fn ->
      assert {:ok, api_key} = Auth.create_api_key(user, name: "meta", metadata: %{env: "ci"})
      assert api_key.metadata == %{"env" => "ci"}
    end)

    with_api_key_config([key_expiration: [default_expires_in: 86_400]], fn ->
      assert {:ok, api_key} = Auth.create_api_key(user, name: "day")
      assert DateTime.diff(api_key.expires_at, DateTime.utc_now(), :second) in 86_300..86_400
    end)

    with_api_key_config([key_expiration: [disable_custom_expires_time: true]], fn ->
      assert {:error, :expiration_disabled} = Auth.create_api_key(user, expires_in: 86_400)
    end)

    with_api_key_config([starting_characters_config: [characters_length: 8]], fn ->
      assert {:ok, api_key} = Auth.create_api_key(user, prefix: "pup_")
      assert api_key.start == String.slice(api_key.key, 0, 8)
    end)

    with_api_key_config(
      [default_permissions: fn _user -> %{projects: ["read"]} end],
      fn ->
        assert {:ok, api_key} = Auth.create_api_key(user, name: "defaults")
        assert api_key.permissions == %{"projects" => ["read"]}
      end
    )
  end

  test "a tenant-scoped key authenticates that tenant and dies with the membership" do
    owner = confirmed_user()
    user = confirmed_user()
    stranger = confirmed_user()
    slug = "api-#{System.unique_integer([:positive])}"
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: slug})
    {:ok, member} = Tenants.add_member(owner, tenant, %{user_id: user.id, role: ["member"]})

    assert {:error, :not_a_member} =
             Auth.create_api_key(stranger, name: "nope", tenant_id: tenant.id)

    assert {:ok, scoped} =
             Auth.create_api_key(user, name: "ci", prefix: "pup_", organization_id: tenant.id)

    assert scoped.active_tenant_id == tenant.id
    assert scoped.organization_id == tenant.id
    assert scoped.reference_id == user.id

    assert {:ok, unscoped} = Auth.create_api_key(user, name: "personal", prefix: "pup_")
    assert is_nil(unscoped.active_tenant_id)

    session = Auth.generate_session_token(user)
    assert {:ok, _} = Tenants.set_active_tenant(session, tenant.id)

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer " <> scoped.key)
      |> Bearer.call([])

    assert conn.assigns.current_user.id == user.id
    assert conn.assigns.current_tenant_id == tenant.id
    assert conn.assigns.current_api_key.id == scoped.id

    assert {:ok, %{api_keys: [listed], total: 1}} =
             Auth.list_api_keys(user, organization_id: tenant.id)

    assert listed.id == scoped.id

    Repo.delete!(member)

    assert %{valid: false, error: %{code: "USER_NOT_MEMBER_OF_ORGANIZATION"}} =
             Auth.verify_api_key(scoped.key)

    assert Repo.get(UserToken, scoped.id)

    assert {:ok, readded} =
             Tenants.add_member(owner, tenant, %{user_id: user.id, role: ["member"]})

    assert %{valid: true} = Auth.verify_api_key(scoped.key)
    assert {:ok, _} = Tenants.remove_member(owner, readded.id)

    refute Repo.get(UserToken, scoped.id)
    assert %{valid: false} = Auth.verify_api_key(scoped.key)
    assert %{valid: true} = Auth.verify_api_key(unscoped.key)
    assert Auth.fetch_user_by_session_token(session).id == user.id

    session_row = Repo.get_by!(UserToken, token: session, context: "session")
    assert is_nil(session_row.active_tenant_id)
  end

  test "leaving a tenant revokes that user's scoped keys and keeps the owner's" do
    owner = confirmed_user()
    user = confirmed_user()
    slug = "leave-#{System.unique_integer([:positive])}"
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: slug})
    assert {:ok, _} = Tenants.add_member(owner, tenant, %{user_id: user.id, role: ["member"]})

    assert {:ok, user_key} = Auth.create_api_key(user, name: "user", tenant_id: tenant.id)
    assert {:ok, owner_key} = Auth.create_api_key(owner, name: "owner", tenant_id: tenant.id)

    assert {:ok, _} = Tenants.leave_tenant(user, tenant_id: tenant.id)
    refute Repo.get(UserToken, user_key.id)
    assert Repo.get(UserToken, owner_key.id)
    assert %{valid: true} = Auth.verify_api_key(owner_key.key)
  end

  test "deleting a tenant revokes scoped keys and keeps sessions and unscoped keys" do
    owner = confirmed_user()
    slug = "gone-#{System.unique_integer([:positive])}"
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: slug})
    assert {:ok, scoped} = Auth.create_api_key(owner, name: "scoped", tenant_id: tenant.id)
    assert {:ok, open} = Auth.create_api_key(owner, name: "open")
    session = Auth.generate_session_token(owner)
    assert {:ok, _} = Tenants.set_active_tenant(session, tenant.id)

    assert {:ok, _} = Tenants.delete_tenant(owner, tenant_id: tenant.id)
    refute Repo.get(UserToken, scoped.id)
    assert %{valid: true} = Auth.verify_api_key(open.key)
    assert Auth.fetch_user_by_session_token(session).id == owner.id

    session_row = Repo.get_by!(UserToken, token: session, context: "session")
    assert is_nil(session_row.active_tenant_id)
  end

  defp confirmed_user do
    user = Fixtures.user_fixture()
    {:ok, user, _} = Auth.confirm_user_email(user)
    user
  end

  defp with_api_key_config(config, fun) do
    previous = Application.get_env(:auth_kit, :api_key)
    Application.put_env(:auth_kit, :api_key, config)

    try do
      fun.()
    after
      if previous do
        Application.put_env(:auth_kit, :api_key, previous)
      else
        Application.delete_env(:auth_kit, :api_key)
      end
    end
  end
end
