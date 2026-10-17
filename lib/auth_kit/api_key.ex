defmodule AuthKit.ApiKey do
  @moduledoc """
  API keys for scripts and CI, modeled on Better Auth's API key plugin.

  https://better-auth.com/docs/plugins/api-key

  Keys live in the user token table with context `"api"`. The plaintext is
  returned once from `create_api_key/2`. The row stores `SHA-256` of that
  string in `token`, the same digest email tokens use. `prefix` and `start`
  are the non-secret parts safe to show in a list.

  | Better Auth | AuthKit |
  | --- | --- |
  | `createApiKey` | `create_api_key/2` |
  | `verifyApiKey` | `verify_api_key/2` |
  | `getApiKey` | `get_api_key/2` |
  | `updateApiKey` | `update_api_key/3` |
  | `deleteApiKey` | `delete_api_key/2` (`revoke_api_key/2`) |
  | `listApiKeys` | `list_api_keys/2` |
  | `deleteAllExpiredApiKeys` | `delete_all_expired_api_keys/1` |

  `AuthKit.Auth` exposes the same functions. The user is an argument here.
  Better Auth reads the user from the session when the call comes from HTTP.

  A key is owned by a user (`reference_id` / `user_id`). Pass `tenant_id:`
  or `organization_id:` to scope it to a tenant the user belongs to
  (`active_tenant_id`). Removing that membership revokes the scoped keys.
  Better Auth can instead make the organization itself the owner
  (`references: "organization"`). That mode is not built yet.

  Configure defaults with `config :auth_kit, api_key: [...]`. Option names
  match the plugin in snake_case: `:default_prefix`, `:default_key_length`
  (64), `:require_name`, `:enable_metadata` (false), `:default_permissions`,
  `:minimum_name_length`, `:maximum_name_length` (32), `:minimum_prefix_length`,
  `:maximum_prefix_length` (32), `:api_key_headers`, `:starting_characters_config`
  (`should_store`, `characters_length`), and `:key_expiration`
  (`default_expires_in` in seconds, `disable_custom_expires_time`,
  `min_expires_in` and `max_expires_in` in days).

  `expires_in` is seconds, matching Better Auth's create body. `nil` means
  no expiry unless `:default_expires_in` is set. Rate limiting and refill
  are not implemented; passing those options returns `{:error, {:not_supported, field}}`.

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
  @unsupported ~w(refill_amount refill_interval rate_limit_enabled rate_limit_max rate_limit_time_window)a
  @updatable ~w(name enabled remaining metadata permissions expires_in)a
  @api_fields ~w(name prefix start config_id enabled last_request metadata permissions remaining updated_at)a

  @messages %{
    "INVALID_API_KEY" => "Invalid API key.",
    "KEY_DISABLED" => "API Key is disabled",
    "KEY_EXPIRED" => "API Key has expired",
    "KEY_NOT_FOUND" => "API Key not found",
    "USAGE_EXCEEDED" => "API Key has reached its usage limit",
    "USER_NOT_MEMBER_OF_ORGANIZATION" =>
      "You are not a member of the organization that owns this API key."
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

  @doc """
  Creates an API key.

  Returns `{:ok, key}` where `key` includes `:key`, the plaintext, one time.
  Later reads omit `:key`. `{:error, reason}` is an atom such as
  `:invalid_name_length`, `:invalid_prefix`, `:expires_in_too_small`,
  `:metadata_disabled`, `:not_a_member`, or `{:not_supported, field}`.

  ## Options

    * `:name` — label stored for the list view
    * `:expires_in` — lifetime in seconds, or omit/`nil` for the configured default
    * `:prefix` — prepended to the key, for example `"pup_"`
    * `:metadata` — map, only when `:enable_metadata` is true
    * `:permissions` — `%{resource => [action]}`
    * `:remaining` — uses left before the key is rejected, or `nil` for no cap
    * `:config_id` — stored and used to filter verify and list. Defaults to `"default"`
    * `:tenant_id` or `:organization_id` — tenant scope; the user must be a member
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
         {:ok, metadata} <- validate_metadata(Keyword.get(opts, :metadata)),
         {:ok, permissions} <- resolve_permissions(user, Keyword.get(opts, :permissions)),
         :ok <- validate_remaining(Keyword.get(opts, :remaining)),
         {:ok, config_id} <- validate_config_id(opts[:config_id] || "default"),
         {:ok, tenant_id} <- resolve_tenant(user, opts) do
      insert_key(user, opts, metadata, permissions, config_id, tenant_id)
    end
  end

  @doc """
  Checks `key`.

  Returns `%{valid: boolean, error: nil | %{code: code, message: message}, key: metadata | nil}`.
  `key` in that map never includes the secret. A valid check sets `last_request`
  and, when `:remaining` is a number, decrements it. An expired key and a key
  whose remaining count is already `0` are deleted.

  ## Options

    * `:config_id` — when set, the key's `config_id` must match
    * `:permissions` — each action must be present on the key
  """
  def verify_api_key(key, opts \\ []) when is_binary(key) and is_list(opts) do
    ensure_fields!()
    result = present(do_verify(key, opts))
    _ = delete_all_expired_api_keys()
    result
  end

  @doc false
  def authenticate(key) when is_binary(key) do
    if fields_ready?() do
      result =
        case do_verify(key, []) do
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
  """
  def get_api_key(user, id) when is_binary(id) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, token} <- fetch_owned(user, id) do
      {:ok, to_metadata(token)}
    end
  end

  def get_api_key(user, _id) do
    ensure_fields!()
    with :ok <- ensure_user(user), do: {:error, :not_found}
  end

  @doc """
  Updates a key owned by `user`.

  Accepts `:name`, `:enabled`, `:remaining`, `:metadata`, `:permissions`,
  and `:expires_in` (seconds from now, or `nil` to clear the expiry).
  Returns `{:ok, metadata}` without the secret.
  """
  def update_api_key(user, id, opts \\ [])

  def update_api_key(user, id, opts) when is_binary(id) and is_list(opts) do
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

  def update_api_key(user, _id, opts) when is_list(opts) do
    ensure_fields!()
    with :ok <- ensure_user(user), do: {:error, :not_found}
  end

  @doc """
  Lists `user`'s API keys.

  Returns `{:ok, %{api_keys: [metadata], total: n, limit: limit, offset: offset}}`.
  Metadata includes `name`, `prefix`, `start`, `created_at`, `last_request`,
  and `expires_at`. The secret is not included.

  ## Options

    * `:config_id`
    * `:tenant_id` or `:organization_id` — only keys scoped to that tenant
    * `:limit`, `:offset`
    * `:sort_by` — `"createdAt"`, `"name"`, or `"expiresAt"` (snake_case works too)
    * `:sort_direction` — `"asc"` or `"desc"` (default `"desc"`)
  """
  def list_api_keys(user, opts \\ []) when is_list(opts) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         :ok <- reject_unsupported(opts),
         {:ok, config_id} <- filter_config_id(opts),
         {:ok, tenant_id} <- resolve_tenant(user, opts),
         {:ok, field, direction} <- sort(opts),
         {:ok, limit, offset} <- pagination(opts) do
      _ = delete_all_expired_api_keys()

      base =
        from t in schema(),
          where: t.user_id == ^user.id and t.context == ^context()

      base = if config_id, do: from(t in base, where: t.config_id == ^config_id), else: base

      base =
        if tenant_id, do: from(t in base, where: t.active_tenant_id == ^tenant_id), else: base

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
  sessions are left in place. This is Better Auth's `deleteApiKey`.
  """
  def delete_api_key(user, id) when is_binary(id) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, token} <- fetch_owned(user, id) do
      Repo.delete!(token)
      {:ok, %{success: true}}
    end
  end

  def delete_api_key(user, _id) do
    ensure_fields!()
    with :ok <- ensure_user(user), do: {:error, :not_found}
  end

  @doc """
  Deletes one API key. Same as `delete_api_key/2`.
  """
  def revoke_api_key(user, id), do: delete_api_key(user, id)

  @doc """
  Deletes API keys whose `expires_at` is in the past.

  Returns `{:ok, count}`. Calls from create, list, and verify share a 10
  second cooldown, matching Better Auth. Pass `force: true` to ignore it.
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

  defp insert_key(user, opts, metadata, permissions, config_id, tenant_id) do
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
      prefix: prefix,
      start: starting(plaintext),
      config_id: config_id,
      enabled: true,
      last_request: nil,
      metadata: metadata,
      permissions: permissions,
      remaining: Keyword.get(opts, :remaining),
      updated_at: now
    }

    attrs =
      if tenant_id do
        Map.put(attrs, :active_tenant_id, tenant_id)
      else
        attrs
      end

    case schema() |> struct(attrs) |> Repo.insert() do
      {:ok, token} -> {:ok, Map.put(to_metadata(token), :key, plaintext)}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp do_verify(key, opts) do
    with {:ok, config_id} <- optional_config_id(opts),
         {:ok, required} <- optional_permissions(opts) do
      case lookup(hash(key), config_id) do
        nil -> failure("INVALID_API_KEY")
        found -> authorize(found, required)
      end
    end
  end

  defp present({:ok, _user, token}), do: %{valid: true, error: nil, key: to_metadata(token)}
  defp present({:error, %{} = error}), do: %{valid: false, error: error, key: nil}

  defp authorize({token, user}, required) do
    cond do
      token.enabled == false ->
        failure("KEY_DISABLED")

      expired?(token) ->
        Repo.delete!(token)
        failure("KEY_EXPIRED")

      not permissions_ok?(token.permissions, required) ->
        failure("KEY_NOT_FOUND")

      not member_ok?(token) ->
        failure("USER_NOT_MEMBER_OF_ORGANIZATION")

      token.remaining == 0 ->
        Repo.delete!(token)
        failure("USAGE_EXCEEDED")

      true ->
        claim(token, user)
    end
  end

  defp claim(%{remaining: nil} = token, user), do: stamp(token, user, nil)

  defp claim(%{remaining: remaining} = token, user)
       when is_integer(remaining) and remaining > 0 do
    stamp(token, user, remaining)
  end

  defp claim(_token, _user), do: failure("USAGE_EXCEEDED")

  defp stamp(token, user, nil) do
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

  defp stamp(token, user, remaining) do
    now = DateTime.utc_now()

    {count, _} =
      from(t in schema(), where: t.id == ^token.id and t.remaining > 0)
      |> Repo.update_all(inc: [remaining: -1], set: [last_request: now, updated_at: now])

    if count == 1 do
      {:ok, user, %{token | remaining: remaining - 1, last_request: now, updated_at: now}}
    else
      failure("USAGE_EXCEEDED")
    end
  end

  defp lookup(hashed, config_id) do
    query =
      from t in schema(),
        join: user in assoc(t, :user),
        where: t.token == ^hashed and t.context == ^context(),
        select: {t, user}

    query =
      if is_binary(config_id) do
        from [t, user] in query, where: t.config_id == ^config_id
      else
        query
      end

    Repo.one(query)
  end

  defp expired?(%{expires_at: nil}), do: false

  defp expired?(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp member_ok?(token) do
    case active_tenant_id(token) do
      nil ->
        true

      tenant_id ->
        Repo.exists?(
          from m in Config.tenant_member_schema(),
            where: m.user_id == ^token.user_id and m.tenant_id == ^tenant_id
        )
    end
  end

  defp permissions_ok?(_stored, nil), do: true
  defp permissions_ok?(_stored, required) when required == %{}, do: true

  defp permissions_ok?(nil, required) when is_map(required) and map_size(required) > 0, do: false

  defp permissions_ok?(stored, required) when is_map(stored) and is_map(required) do
    Enum.all?(required, fn {resource, actions} ->
      held = Map.get(stored, to_string(resource), [])
      held = if is_list(held), do: Enum.map(held, &to_string/1), else: []
      Enum.all?(List.wrap(actions), &(to_string(&1) in held))
    end)
  end

  defp permissions_ok?(_stored, _required), do: false

  defp to_metadata(token) do
    tenant_id = active_tenant_id(token)

    %{
      id: token.id,
      config_id: token.config_id || "default",
      name: token.name,
      prefix: token.prefix,
      start: token.start,
      enabled: token.enabled != false,
      expires_at: token.expires_at,
      reference_id: token.user_id,
      user_id: token.user_id,
      organization_id: tenant_id,
      active_tenant_id: tenant_id,
      last_request: token.last_request,
      metadata: token.metadata,
      permissions: token.permissions,
      remaining: token.remaining,
      created_at: token.inserted_at,
      updated_at: token.updated_at
    }
  end

  defp active_tenant_id(token), do: Map.get(token, :active_tenant_id)

  defp fetch_owned(user, id) do
    case cast_id(id) do
      {:ok, id} ->
        case Repo.get(schema(), id) do
          %{user_id: user_id} = token ->
            if token.context == context() and user_id == user.id do
              {:ok, token}
            else
              {:error, :not_found}
            end

          nil ->
            {:error, :not_found}
        end

      :error ->
        {:error, :not_found}
    end
  end

  defp cast_id(id) when is_binary(id) do
    case Ecto.UUID.cast(id) do
      {:ok, id} -> {:ok, id}
      :error -> :error
    end
  end

  defp cast_id(_id), do: :error

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

  defp cast_update(:remaining, value) do
    case validate_remaining(value) do
      :ok -> {:ok, {:remaining, value}}
      error -> error
    end
  end

  defp cast_update(:metadata, value) do
    case validate_metadata(value) do
      {:ok, metadata} -> {:ok, {:metadata, metadata}}
      error -> error
    end
  end

  defp cast_update(:permissions, value) do
    case normalize_permissions(value) do
      {:ok, permissions} -> {:ok, {:permissions, permissions}}
      error -> error
    end
  end

  defp cast_update(:expires_in, nil), do: {:ok, {:expires_at, nil}}

  defp cast_update(:expires_in, value) do
    case validate_expires_in(value) do
      :ok -> {:ok, {:expires_at, DateTime.add(DateTime.utc_now(), value, :second)}}
      error -> error
    end
  end

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

  # SQLite rejects OFFSET unless LIMIT is present. A negative limit means no cap.
  defp order_page(query, field, direction, nil, 0) do
    from t in query, order_by: [{^direction, ^field}, asc: t.id]
  end

  defp order_page(query, field, direction, nil, offset) do
    from t in query,
      order_by: [{^direction, ^field}, asc: t.id],
      limit: fragment("-1"),
      offset: ^offset
  end

  defp order_page(query, field, direction, limit, offset) do
    from t in query,
      order_by: [{^direction, ^field}, asc: t.id],
      limit: ^limit,
      offset: ^offset
  end

  defp filter_config_id(opts) do
    case Keyword.get(opts, :config_id) do
      nil -> {:ok, nil}
      id when is_binary(id) and id != "" -> {:ok, id}
      _ -> {:error, :invalid_config_id}
    end
  end

  defp optional_config_id(opts) do
    case Keyword.get(opts, :config_id) do
      nil -> {:ok, nil}
      id when is_binary(id) and id != "" -> {:ok, id}
      _ -> failure("INVALID_API_KEY")
    end
  end

  defp optional_permissions(opts) do
    if Keyword.has_key?(opts, :permissions) do
      case normalize_permissions(opts[:permissions]) do
        {:ok, permissions} ->
          {:ok, permissions}

        {:error, :invalid_permissions} ->
          {:error,
           %{
             code: "INVALID_PERMISSIONS",
             message: "permissions must map a resource to a list of actions"
           }}
      end
    else
      {:ok, nil}
    end
  end

  defp resolve_tenant(user, opts) do
    case tenant_id_opt(opts) do
      {:ok, nil} ->
        {:ok, nil}

      {:ok, id} ->
        ensure_tenant_field!()

        with {:ok, tenant} <- fetch_tenant(id),
             :ok <- ensure_member(user, tenant.id) do
          {:ok, tenant.id}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp tenant_id_opt(opts) do
    tenant = Keyword.get(opts, :tenant_id)
    organization = Keyword.get(opts, :organization_id)

    cond do
      is_nil(tenant) and is_nil(organization) -> {:ok, nil}
      is_nil(tenant) -> {:ok, organization}
      is_nil(organization) -> {:ok, tenant}
      tenant == organization -> {:ok, tenant}
      true -> {:error, :tenant_mismatch}
    end
  end

  defp fetch_tenant(id) when is_binary(id) do
    try do
      case Repo.get(Config.tenant_schema(), id) do
        nil -> {:error, :not_found}
        tenant -> {:ok, tenant}
      end
    rescue
      Ecto.Query.CastError -> {:error, :not_found}
    end
  end

  defp fetch_tenant(_id), do: {:error, :not_found}

  defp ensure_member(user, tenant_id) do
    exists =
      Repo.exists?(
        from m in Config.tenant_member_schema(),
          where: m.user_id == ^user.id and m.tenant_id == ^tenant_id
      )

    if exists, do: :ok, else: {:error, :not_a_member}
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

  defp ensure_user(%{id: id} = user) when is_binary(id) do
    if is_struct(user, Config.user_schema()), do: :ok, else: {:error, :invalid_user}
  end

  defp ensure_user(_user), do: {:error, :invalid_user}

  defp ensure_same_user(user, opts) do
    case Keyword.get(opts, :user_id) do
      nil -> :ok
      id when id == user.id -> :ok
      _other -> {:error, :invalid_user}
    end
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
    max = conf(:maximum_prefix_length, 32)

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

  defp validate_remaining(nil), do: :ok
  defp validate_remaining(count) when is_integer(count) and count >= 0, do: :ok
  defp validate_remaining(_count), do: {:error, :invalid_remaining}

  defp validate_config_id(id) when is_binary(id) do
    if id == "" or String.length(id) > 255 do
      {:error, :invalid_config_id}
    else
      {:ok, id}
    end
  end

  defp validate_config_id(_id), do: {:error, :invalid_config_id}

  defp validate_metadata(nil), do: {:ok, nil}
  defp validate_metadata(%_{}), do: {:error, :invalid_metadata}

  defp validate_metadata(metadata) when is_map(metadata) do
    if conf(:enable_metadata, false) do
      {:ok, stringify_keys(metadata)}
    else
      {:error, :metadata_disabled}
    end
  end

  defp validate_metadata(_metadata), do: {:error, :invalid_metadata}

  defp resolve_permissions(user, nil) do
    case default_permissions(user) do
      nil -> {:ok, nil}
      :invalid -> {:error, :invalid_permissions}
      permissions -> normalize_permissions(permissions)
    end
  end

  defp resolve_permissions(_user, permissions), do: normalize_permissions(permissions)

  defp default_permissions(user) do
    case conf(:default_permissions, nil) do
      fun when is_function(fun, 1) -> fun.(user)
      fun when is_function(fun, 0) -> fun.()
      %{} = permissions -> permissions
      nil -> nil
      _other -> :invalid
    end
  end

  defp normalize_permissions(nil), do: {:ok, nil}

  defp normalize_permissions(permissions) when is_list(permissions) do
    if Keyword.keyword?(permissions) do
      normalize_permissions(Map.new(permissions))
    else
      {:error, :invalid_permissions}
    end
  end

  defp normalize_permissions(%_{}), do: {:error, :invalid_permissions}

  defp normalize_permissions(permissions) when is_map(permissions) do
    result =
      Enum.reduce_while(permissions, %{}, fn {resource, actions}, acc ->
        cond do
          not (is_binary(resource) or is_atom(resource)) ->
            {:halt, :error}

          not is_list(actions) or not Enum.all?(actions, &(is_binary(&1) or is_atom(&1))) ->
            {:halt, :error}

          true ->
            {:cont, Map.put(acc, to_string(resource), Enum.map(actions, &to_string/1))}
        end
      end)

    case result do
      :error -> {:error, :invalid_permissions}
      permissions -> {:ok, permissions}
    end
  end

  defp normalize_permissions(_permissions), do: {:error, :invalid_permissions}

  defp resolved_prefix(opts), do: opts[:prefix] || conf(:default_prefix, nil)

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

  defp starting(plaintext) do
    config = conf(:starting_characters_config, [])

    if Keyword.get(config, :should_store, true) == false do
      nil
    else
      length = Keyword.get(config, :characters_length, 6)
      length = if is_integer(length) and length > 0, do: length, else: 6
      String.slice(plaintext, 0, length)
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

  defp stringify_keys(%_{} = value), do: value

  defp stringify_keys(value) when is_map(value) do
    Map.new(value, fn
      {key, nested} when is_atom(key) -> {Atom.to_string(key), stringify_keys(nested)}
      {key, nested} -> {key, stringify_keys(nested)}
    end)
  end

  defp stringify_keys(value) when is_list(value), do: Enum.map(value, &stringify_keys/1)
  defp stringify_keys(value), do: value

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

  defp schema, do: Config.user_token_schema()
end
