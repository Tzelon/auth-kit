defmodule AuthKit.ApiKey do
  @moduledoc """
  API keys for scripts and CI.

  Keys live in the user token table with context `"api"`. The plaintext is
  returned once from `create_api_key/2`. The row stores `SHA-256` of that
  string in `token`, the same digest email tokens use. `prefix` is the
  configured, non-secret prefix safe to show in a list. It never contains
  the generated key.

  `AuthKit.Auth` defines the same functions as this module. Both take the
  user struct, except verify, which takes the plaintext key:

      AuthKit.ApiKey.create_api_key(user, name: "ci", prefix: "pup_")
      AuthKit.Auth.create_api_key(user, name: "ci", prefix: "pup_")

  The key belongs to that user, stored as `user_id`. Pass `tenant_id:` to
  limit it to a tenant the user belongs to. The tenant id is stored in
  `active_tenant_id`, `tenant_scoped` is set, and `tenant_member_id` is the
  membership row from that moment. Deleting that membership, including a
  raw delete, retires the key. A later membership for the same user does
  not revive it. Deleting the tenant row, including a raw `Repo.delete/1`,
  clears `active_tenant_id` and the scoped key stops authenticating. An
  unscoped key has `tenant_scoped` false and stays valid. Session rows
  share `active_tenant_id` and only have that column cleared.

  Configure defaults with `config :auth_kit, api_key: [...]`:
  `:default_prefix`, `:default_key_length` (64), `:require_name`,
  `:minimum_name_length`, `:maximum_name_length` (32),
  `:minimum_prefix_length`, `:maximum_prefix_length` (32),
  `:api_key_headers`, and `:key_expiration` (`default_expires_in` in
  seconds, `disable_custom_expires_time`, `min_expires_in` and
  `max_expires_in` in days).

  `expires_in` is seconds. `nil` means no expiry unless `:default_expires_in`
  is set. A key owned by the tenant, per-key permissions, and request
  quotas are sketched in
  `docs/contributing/proposals/001-api-key-ownership-and-limits.md`.
  Passing those options returns `{:error, {:not_supported, field}}`.

  Ids follow the host schema. `get_api_key/2`, `update_api_key/3`,
  `delete_api_key/2`, and `revoke_api_key/2` cast with the token schema's
  primary key type, so an integer id works when that is the key's id.
  User ids are cast the same way.

  The user token schema needs `auth_kit_api_key_fields/0`, and a scoped key
  also needs `auth_kit_active_tenant_field/0`. See `docs/api_keys.md`.
  """

  import Ecto.Changeset
  import Ecto.Query

  alias AuthKit.Config
  alias AuthKit.Repo

  @context "api"
  @alphabet ~c"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  @alphabet_span 52 * 4
  @prefix ~r/^[a-zA-Z0-9_-]+$/
  @sweep_cooldown_ms 10_000

  # Hard cap so a large `maximum_prefix_length` cannot turn `prefix` into
  # a copy of the credential. The stored value is the configured prefix
  # only; generated key bytes are never written.
  @max_stored_prefix 32

  # SQLite requires LIMIT when OFFSET is set. A negative limit is unlimited
  # there and an error on PostgreSQL and MySQL.
  @unbounded_limit 2_147_483_647

  @unsupported ~w(
    refill_amount
    refill_interval
    rate_limit_enabled
    rate_limit_max
    rate_limit_time_window
    permissions
    remaining
    metadata
    config_id
    organization_id
  )a

  @updatable ~w(name enabled)a
  @api_fields ~w(name prefix enabled last_request updated_at tenant_scoped)a
  @schema_override_key {__MODULE__, :schema}

  @messages %{
    "INVALID_API_KEY" => "Invalid API key.",
    "KEY_DISABLED" => "API Key is disabled",
    "KEY_EXPIRED" => "API Key has expired",
    "USER_NOT_MEMBER_OF_TENANT" => "You are not a member of the tenant this API key is scoped to."
  }

  @doc """
  The user token context for an API key.
  """
  def context, do: @context

  @doc false
  def fields_ready? do
    fields = schema().__schema__(:fields)
    Enum.all?(@api_fields, &(&1 in fields))
  end

  @doc false
  def put_schema(schema) when is_atom(schema) do
    Process.put(@schema_override_key, schema)
  end

  @doc false
  def delete_schema do
    Process.delete(@schema_override_key)
  end

  @doc """
  Creates an API key.

  Returns `{:ok, key}` where `key` includes `:key`, the plaintext, one time.
  Later reads omit `:key`. `{:error, reason}` is an atom such as
  `:invalid_name_length`, `:invalid_prefix`, `:expires_in_too_small`,
  `:not_a_member`, or `{:not_supported, field}`.

  ## Options

    * `:name` — label stored for the list view
    * `:expires_in` — lifetime in seconds, or omit/`nil` for the configured default
    * `:prefix` — prepended to the key and stored for display, for example `"pup_"`.
      Only this prefix is stored. Generated key bytes are not.
    * `:tenant_id` — tenant scope; the user must be a member
    * `:user_id` — must match `user.id` when set
  """
  def create_api_key(user, opts \\ []) when is_list(opts) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         :ok <- ensure_same_user(user, opts),
         :ok <- reject_unsupported(opts),
         :ok <- validate_name(Keyword.get(opts, :name)),
         :ok <- validate_prefix(resolved_prefix(opts)),
         :ok <- validate_expires_in(Keyword.get(opts, :expires_in)),
         {:ok, scope} <- resolve_tenant(user, opts) do
      insert_key(user, opts, scope)
    end
  end

  @doc """
  Checks `key`.

  Returns `%{valid: boolean, error: nil | %{code: code, message: message}, key: metadata | nil}`.
  `key` in that map never includes the secret. A valid check sets `last_request`.
  An expired key is deleted. A key whose tenant was deleted is rejected.

  Passing a permissions, metadata, rate-limit, or refill option returns
  `{:error, {:not_supported, field}}`.
  """
  def verify_api_key(key, opts \\ []) when is_binary(key) and is_list(opts) do
    ensure_fields!()

    with :ok <- reject_unsupported(opts) do
      result = present(do_verify(key))
      _ = delete_all_expired_api_keys()
      result
    end
  end

  @doc false
  def authenticate(key) when is_binary(key) do
    if fields_ready?() do
      result =
        case do_verify(key) do
          {:ok, user, token} -> {:ok, user, to_metadata(token)}
          _ -> :error
        end

      _ = delete_all_expired_api_keys()
      result
    else
      :error
    end
  end

  @doc """
  Returns `{:ok, metadata}` for one of `user`'s keys, without the secret.

  `id` is cast with the token schema's primary key type.
  """
  def get_api_key(user, id) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, token} <- fetch_owned(user, id) do
      {:ok, to_metadata(token)}
    end
  end

  @doc """
  Updates a key owned by `user`.

  Accepts `:name` and `:enabled`. Returns `{:ok, metadata}` without the secret.
  `id` is cast with the token schema's primary key type.
  """
  def update_api_key(user, id, opts \\ [])

  def update_api_key(user, id, opts) when is_list(opts) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         :ok <- reject_unsupported(opts),
         {:ok, token} <- fetch_owned(user, id),
         {:ok, changes} <- update_changes(opts) do
      case token |> change(changes) |> Repo.update() do
        {:ok, token} -> {:ok, to_metadata(token)}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end

  @doc """
  Lists `user`'s API keys.

  Returns `{:ok, %{api_keys: [metadata], total: n, limit: limit, offset: offset}}`.
  Metadata includes `name`, `prefix`, `created_at`, `last_request`, and
  `expires_at`. The secret is not included. `prefix` is the configured
  prefix, not the key.

  ## Options

    * `:tenant_id` — only keys scoped to that tenant
    * `:limit`, `:offset` — `offset` without `limit` returns the rest of the rows
    * `:sort_by` — `"createdAt"`, `"name"`, or `"expiresAt"` (snake_case works too)
    * `:sort_direction` — `"asc"` or `"desc"` (default `"desc"`)
  """
  def list_api_keys(user, opts \\ []) when is_list(opts) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         :ok <- reject_unsupported(opts),
         {:ok, scope} <- resolve_tenant(user, opts),
         {:ok, field, direction} <- sort(opts),
         {:ok, limit, offset} <- pagination(opts) do
      _ = delete_all_expired_api_keys()

      base =
        from t in schema(),
          where: t.user_id == ^user.id and t.context == ^context()

      base =
        if scope,
          do: from(t in base, where: t.active_tenant_id == ^scope.tenant_id),
          else: base

      total = Repo.one(from t in base, select: count(t.id)) || 0

      keys =
        base
        |> order_page(field, direction, limit, offset)
        |> Repo.all()
        |> Enum.map(&to_metadata/1)

      {:ok, %{api_keys: keys, total: total, limit: limit, offset: offset}}
    end
  end

  @doc """
  Deletes one API key owned by `user`.

  Returns `{:ok, %{success: true}}`. A missing key, a key owned by someone
  else, and a session token id are `{:error, :not_found}`. Other keys and
  sessions are left in place.

  `id` is cast with the token schema's primary key type.
  """
  def delete_api_key(user, id) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, id} <- cast_schema_id(schema(), id) do
      {count, _} =
        from(t in schema(),
          where: t.id == ^id and t.user_id == ^user.id and t.context == ^context()
        )
        |> Repo.delete_all()

      if count == 1 do
        {:ok, %{success: true}}
      else
        {:error, :not_found}
      end
    else
      :error -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Deletes one API key. Same as `delete_api_key/2`.
  """
  def revoke_api_key(user, id), do: delete_api_key(user, id)

  @doc """
  Deletes API keys whose `expires_at` is in the past.

  Returns `{:ok, count}`. Calls from create, list, and verify share a 10
  second cooldown. Pass `force: true` to ignore it.
  Session tokens are not deleted.
  """
  def delete_all_expired_api_keys(opts \\ []) when is_list(opts) do
    ensure_fields!()

    if Keyword.get(opts, :force, false) or sweep_due?() do
      now = DateTime.utc_now()

      {count, _} =
        from(t in schema(),
          where: t.context == ^context() and not is_nil(t.expires_at) and t.expires_at <= ^now
        )
        |> Repo.delete_all()

      :persistent_term.put(sweep_key(), System.monotonic_time(:millisecond))
      {:ok, count}
    else
      {:ok, 0}
    end
  end

  @doc false
  def revoke_scoped(user_id, tenant_id) do
    from(t in schema(),
      where:
        t.context == ^context() and t.user_id == ^user_id and t.active_tenant_id == ^tenant_id
    )
    |> Repo.delete_all()
  end

  @doc false
  def by_tenant_query(tenant_id) do
    from(t in schema(), where: t.context == ^context() and t.active_tenant_id == ^tenant_id)
  end

  defp insert_key(user, opts, scope) do
    prefix = resolved_prefix(opts)
    plaintext = (prefix || "") <> random_letters(key_length())
    now = DateTime.utc_now()

    _ = delete_all_expired_api_keys()

    attrs = %{
      token: hash(plaintext),
      context: context(),
      user_id: user.id,
      sent_to: nil,
      expires_at: expires_at(opts),
      name: opts[:name],
      prefix: stored_prefix(prefix, plaintext),
      enabled: true,
      last_request: nil,
      tenant_scoped: not is_nil(scope),
      updated_at: now
    }

    attrs =
      if scope do
        Map.merge(attrs, %{
          active_tenant_id: scope.tenant_id,
          tenant_member_id: scope.member_id
        })
      else
        attrs
      end

    case schema() |> struct(attrs) |> Repo.insert() do
      {:ok, token} -> {:ok, Map.put(to_metadata(token), :key, plaintext)}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp do_verify(key) do
    case lookup(hash(key)) do
      nil -> failure("INVALID_API_KEY")
      found -> authorize(found)
    end
  end

  defp present({:ok, _user, token}), do: %{valid: true, error: nil, key: to_metadata(token)}
  defp present({:error, %{} = error}), do: %{valid: false, error: error, key: nil}

  defp authorize({token, user}) do
    cond do
      token.enabled == false ->
        failure("KEY_DISABLED")

      expired?(token) ->
        delete_token(token.id)
        failure("KEY_EXPIRED")

      not member_ok?(token) ->
        delete_token(token.id)
        failure("USER_NOT_MEMBER_OF_TENANT")

      true ->
        stamp(token, user)
    end
  end

  defp delete_token(id) do
    from(t in schema(), where: t.id == ^id) |> Repo.delete_all()
  end

  defp stamp(token, user) do
    now = DateTime.utc_now()

    {count, _} =
      from(t in schema(), where: t.id == ^token.id)
      |> Repo.update_all(set: [last_request: now, updated_at: now])

    if count == 1 do
      {:ok, user, %{token | last_request: now, updated_at: now}}
    else
      failure("INVALID_API_KEY")
    end
  end

  defp lookup(hashed) do
    Repo.one(
      from t in schema(),
        join: user in assoc(t, :user),
        where: t.token == ^hashed and t.context == ^context(),
        select: {t, user}
    )
  end

  defp expired?(%{expires_at: nil}), do: false

  defp expired?(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  # A scoped key is bound to one membership row. A raw delete nilifies
  # `tenant_member_id`. A later membership is a new row, so the old key
  # stays invalid. Unscoped keys have `tenant_scoped` false.
  defp member_ok?(%{tenant_scoped: true} = token) do
    member_id = Map.get(token, :tenant_member_id)
    tenant_id = active_tenant_id(token)

    case {member_id, tenant_id} do
      {nil, _} ->
        false

      {_, nil} ->
        false

      {member_id, tenant_id} ->
        case Repo.get(Config.tenant_member_schema(), member_id) do
          %{user_id: user_id, tenant_id: ^tenant_id} -> user_id == token.user_id
          _member -> false
        end
    end
  end

  defp member_ok?(_token), do: true

  defp to_metadata(token) do
    tenant_id = active_tenant_id(token)

    %{
      id: token.id,
      name: token.name,
      prefix: token.prefix,
      enabled: token.enabled != false,
      expires_at: token.expires_at,
      reference_id: token.user_id,
      user_id: token.user_id,
      active_tenant_id: tenant_id,
      tenant_member_id: Map.get(token, :tenant_member_id),
      tenant_scoped: token.tenant_scoped == true,
      last_request: token.last_request,
      created_at: token.inserted_at,
      updated_at: token.updated_at
    }
  end

  defp active_tenant_id(token), do: Map.get(token, :active_tenant_id)

  defp fetch_owned(user, id) do
    with {:ok, id} <- cast_schema_id(schema(), id),
         %{user_id: user_id} = token <- Repo.get(schema(), id),
         true <- token.context == context() and user_id == user.id do
      {:ok, token}
    else
      _other -> {:error, :not_found}
    end
  end

  defp update_changes(opts) do
    opts
    |> Keyword.take(@updatable)
    |> Enum.reduce_while({:ok, []}, fn {key, value}, {:ok, acc} ->
      case cast_update(key, value) do
        {:ok, pair} -> {:cont, {:ok, [pair | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, []} -> {:error, :no_values_to_update}
      {:ok, pairs} -> {:ok, [{:updated_at, DateTime.utc_now()} | pairs]}
      {:error, reason} -> {:error, reason}
    end
  end

  defp cast_update(:name, value) do
    case validate_name(value) do
      :ok -> {:ok, {:name, value}}
      error -> error
    end
  end

  defp cast_update(:enabled, value) when is_boolean(value), do: {:ok, {:enabled, value}}
  defp cast_update(:enabled, _value), do: {:error, :invalid_enabled}

  defp sort(opts) do
    with {:ok, field} <- sort_field(Keyword.get(opts, :sort_by)),
         {:ok, direction} <- sort_direction(Keyword.get(opts, :sort_direction)) do
      {:ok, field, direction}
    end
  end

  defp sort_field(nil), do: {:ok, :inserted_at}

  defp sort_field(field) when field in ["createdAt", "created_at", :created_at],
    do: {:ok, :inserted_at}

  defp sort_field(field) when field in ["name", :name], do: {:ok, :name}

  defp sort_field(field) when field in ["expiresAt", "expires_at", :expires_at],
    do: {:ok, :expires_at}

  defp sort_field(_field), do: {:error, :invalid_sort}

  defp sort_direction(nil), do: {:ok, :desc}
  defp sort_direction(direction) when direction in ["asc", :asc], do: {:ok, :asc}
  defp sort_direction(direction) when direction in ["desc", :desc], do: {:ok, :desc}
  defp sort_direction(_direction), do: {:error, :invalid_sort}

  defp pagination(opts) do
    limit = Keyword.get(opts, :limit)
    offset = Keyword.get(opts, :offset, 0)

    cond do
      not is_nil(limit) and not (is_integer(limit) and limit >= 0) ->
        {:error, :invalid_pagination}

      not (is_integer(offset) and offset >= 0) ->
        {:error, :invalid_pagination}

      true ->
        {:ok, limit, offset}
    end
  end

  defp order_page(query, field, direction, nil, 0) do
    from t in query, order_by: [{^direction, ^field}, asc: t.id]
  end

  defp order_page(query, field, direction, nil, offset) do
    from t in query,
      order_by: [{^direction, ^field}, asc: t.id],
      limit: @unbounded_limit,
      offset: ^offset
  end

  defp order_page(query, field, direction, limit, offset) do
    from t in query,
      order_by: [{^direction, ^field}, asc: t.id],
      limit: ^limit,
      offset: ^offset
  end

  defp resolve_tenant(user, opts) do
    case Keyword.get(opts, :tenant_id) do
      nil ->
        {:ok, nil}

      id ->
        ensure_tenant_field!()
        ensure_member_field!()

        with {:ok, tenant} <- fetch_tenant(id),
             {:ok, member} <- fetch_member(user, tenant.id) do
          {:ok, %{tenant_id: tenant.id, member_id: member.id}}
        end
    end
  end

  defp fetch_tenant(id) do
    with {:ok, id} <- cast_schema_id(Config.tenant_schema(), id) do
      case Repo.get(Config.tenant_schema(), id) do
        nil -> {:error, :not_found}
        tenant -> {:ok, tenant}
      end
    else
      :error -> {:error, :not_found}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  defp fetch_member(user, tenant_id) do
    case Repo.get_by(Config.tenant_member_schema(), user_id: user.id, tenant_id: tenant_id) do
      nil -> {:error, :not_a_member}
      member -> {:ok, member}
    end
  end

  defp ensure_tenant_field! do
    if :active_tenant_id in schema().__schema__(:fields) do
      :ok
    else
      raise ArgumentError, """
      Scoped API keys need auth_kit_active_tenant_field/0 on the user token schema.
      """
    end
  end

  defp ensure_member_field! do
    if :tenant_member_id in schema().__schema__(:fields) do
      :ok
    else
      raise ArgumentError, """
      Scoped API keys need tenant_member_id. Configure :tenant_member and call auth_kit_api_key_fields/0 so the membership row can be stored.
      """
    end
  end

  defp ensure_user(%{id: id} = user) when not is_nil(id) do
    if is_struct(user, Config.user_schema()) and
         match?({:ok, _}, cast_schema_id(Config.user_schema(), id)) do
      :ok
    else
      {:error, :invalid_user}
    end
  end

  defp ensure_user(_user), do: {:error, :invalid_user}

  defp ensure_same_user(user, opts) do
    case Keyword.get(opts, :user_id) do
      nil ->
        :ok

      id ->
        with {:ok, cast} <- cast_schema_id(Config.user_schema(), id),
             {:ok, user_id} <- cast_schema_id(Config.user_schema(), user.id) do
          if cast == user_id, do: :ok, else: {:error, :invalid_user}
        else
          _other -> {:error, :invalid_user}
        end
    end
  end

  defp cast_schema_id(schema, id) do
    Ecto.Type.cast(schema.__schema__(:type, :id), id)
  end

  defp reject_unsupported(opts) do
    case Enum.find(@unsupported, &Keyword.has_key?(opts, &1)) do
      nil -> :ok
      key -> {:error, {:not_supported, key}}
    end
  end

  defp validate_name(nil) do
    if conf(:require_name, false), do: {:error, :name_required}, else: :ok
  end

  defp validate_name(name) when is_binary(name) do
    length = String.length(name)
    min = conf(:minimum_name_length, 1)
    max = conf(:maximum_name_length, 32)

    if length < min or length > max, do: {:error, :invalid_name_length}, else: :ok
  end

  defp validate_name(_name), do: {:error, :invalid_name_length}

  defp validate_prefix(nil), do: :ok

  defp validate_prefix(prefix) when is_binary(prefix) do
    length = String.length(prefix)
    min = conf(:minimum_prefix_length, 1)
    max = min(conf(:maximum_prefix_length, @max_stored_prefix), @max_stored_prefix)

    cond do
      not Regex.match?(@prefix, prefix) -> {:error, :invalid_prefix}
      length < min or length > max -> {:error, :invalid_prefix_length}
      true -> :ok
    end
  end

  defp validate_prefix(_prefix), do: {:error, :invalid_prefix}

  defp validate_expires_in(nil), do: :ok

  defp validate_expires_in(seconds) when is_integer(seconds) and seconds > 0 do
    if expiration(:disable_custom_expires_time, false) do
      {:error, :expiration_disabled}
    else
      days = seconds / 86_400
      min = expiration(:min_expires_in, 1)
      max = expiration(:max_expires_in, 365)

      cond do
        is_number(min) and days < min -> {:error, :expires_in_too_small}
        is_number(max) and days > max -> {:error, :expires_in_too_large}
        true -> :ok
      end
    end
  end

  defp validate_expires_in(_seconds), do: {:error, :invalid_expires_in}

  defp resolved_prefix(opts), do: opts[:prefix] || conf(:default_prefix, nil)

  # The column stores the configured prefix and nothing from the generated
  # key. `characters_length` cannot extend it. The result is always strictly
  # shorter than the plaintext credential.
  defp stored_prefix(prefix, plaintext) do
    prefix =
      case prefix do
        value when is_binary(value) -> String.slice(value, 0, @max_stored_prefix)
        _other -> ""
      end

    hidden = byte_size(plaintext) - byte_size(prefix)

    cond do
      prefix == "" -> nil
      hidden < 1 -> nil
      not String.starts_with?(plaintext, prefix) -> nil
      true -> prefix
    end
  end

  defp expires_at(opts) do
    case Keyword.get(opts, :expires_in) do
      seconds when is_integer(seconds) and seconds > 0 ->
        DateTime.add(DateTime.utc_now(), seconds, :second)

      _other ->
        case expiration(:default_expires_in, nil) do
          seconds when is_integer(seconds) and seconds > 0 ->
            DateTime.add(DateTime.utc_now(), seconds, :second)

          _default ->
            nil
        end
    end
  end

  defp key_length do
    case conf(:default_key_length, 64) do
      length when is_integer(length) and length > 0 -> length
      _length -> 64
    end
  end

  defp random_letters(count), do: random_letters(count, [])

  defp random_letters(0, acc), do: acc |> Enum.reverse() |> List.to_string()

  defp random_letters(count, acc) do
    <<byte>> = :crypto.strong_rand_bytes(1)

    if byte < @alphabet_span do
      random_letters(count - 1, [Enum.at(@alphabet, rem(byte, 52)) | acc])
    else
      random_letters(count, acc)
    end
  end

  defp hash(key), do: :crypto.hash(:sha256, key)

  defp failure(code), do: {:error, %{code: code, message: Map.fetch!(@messages, code)}}

  defp sweep_due? do
    now = System.monotonic_time(:millisecond)

    case :persistent_term.get(sweep_key(), nil) do
      nil -> true
      last -> now - last >= @sweep_cooldown_ms
    end
  end

  defp sweep_key, do: {__MODULE__, :last_expired_sweep}

  defp conf(key, default) do
    :auth_kit
    |> Application.get_env(:api_key, [])
    |> Keyword.get(key, default)
  end

  defp expiration(key, default) do
    :auth_kit
    |> Application.get_env(:api_key, [])
    |> Keyword.get(:key_expiration, [])
    |> Keyword.get(key, default)
  end

  defp ensure_fields! do
    missing = @api_fields -- schema().__schema__(:fields)

    if missing != [] do
      raise ArgumentError, """
      The user token schema needs auth_kit_api_key_fields/0 before API keys can be used.
      Missing fields: #{inspect(missing)}

      Add the columns in docs/api_keys.md, then:

          schema "users_tokens" do
            auth_kit_user_token_fields()
            auth_kit_api_key_fields()
          end
      """
    end
  end

  defp schema do
    Process.get(@schema_override_key, Config.user_token_schema())
  end
end
