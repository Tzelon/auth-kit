defmodule AuthKit.Device do
  @moduledoc """
  OAuth 2.0 Device Authorization Grant (RFC 8628) for CLI login.

  A grant is one `users_tokens` row with context `"device"`. The device code
  and the user code are returned once, in plaintext. The row stores SHA-256
  of each, the same digest email tokens and API keys use. Comparisons go
  through `Plug.Crypto.secure_compare/2`.

  The row reuses columns that are already on the token table:

    * `token` — digest of the device code
    * `user_code` — digest of the canonical user code (added by
      `auth_kit_device_fields/0`, with `status` and `interval`)
    * `name` — client id
    * `sent_to` — optional scope
    * `user_id` — approving user; null while the grant is pending, unless
      it was pre-bound with `user_id:`
    * `active_tenant_id` — tenant chosen at approval, when the host passes one
    * `last_request` — last poll that was accepted
    * `expires_at` — when the codes stop working

  A second table would split approval, denial, polling, and expiry across
  rows that have to move together. One row keeps those writes on a single
  primary key. `user_id` and `active_tenant_id` are the linkage. There is
  no separate linkage column.

  Polling returns `:authorization_pending`, `:slow_down`, `:expired_token`,
  `:access_denied`, or `{:ok, token}`. On success the plaintext in
  `access_token` is a user API key from `AuthKit.ApiKey`, returned once.
  The CLI stores it and sends it to `AuthKit.Auth.Bearer` as
  `Authorization: Bearer` or `x-api-key`. It is not a session token.
  Session tokens are browser credentials. A CLI needs a long-lived key the
  user can revoke without signing out of the browser.

  `AuthKit.Auth` defines the same calls as this module.

  The user token schema needs `auth_kit_api_key_fields/0` and
  `auth_kit_device_fields/0`. A tenant on approval also needs
  `auth_kit_active_tenant_field/0`. See `docs/device_flow.md`.
  """

  import Ecto.Changeset
  import Ecto.Query

  alias AuthKit.ApiKey
  alias AuthKit.Config
  alias AuthKit.Repo

  @context "device"
  @grant_type "urn:ietf:params:oauth:grant-type:device_code"
  @alphabet "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  @device_bytes 32
  @max_attempts 3
  @interval_step 5
  @max_interval 300
  @sweep_cooldown_ms 10_000
  @default_expires_in 1800
  @default_interval 5
  @default_user_code_length 8
  @max_client_id 191
  @max_scope 1024

  @device_fields ~w(user_code status interval)a
  @reused_fields ~w(name last_request updated_at tenant_scoped)a

  @descriptions %{
    authorization_pending: "The authorization request is still pending.",
    slow_down: "Polling too frequently. Increase the interval by 5 seconds.",
    expired_token: "The device code has expired.",
    access_denied: "The authorization request was denied.",
    invalid_grant: "The device code is invalid, mismatched, or already used.",
    invalid_client: "The client is not allowed to use the device flow.",
    invalid_request: "The request is missing a required parameter.",
    unsupported_grant_type: "grant_type must be urn:ietf:params:oauth:grant-type:device_code.",
    server_error: "The device code could not be issued.",
    invalid_user: "The user id is not valid.",
    not_a_member: "The user is not a member of that tenant.",
    not_found: "The tenant was not found."
  }

  @dummy_hash :crypto.hash(:sha256, "auth-kit-device-dummy")

  @doc """
  The user token context for a device grant.
  """
  def context, do: @context

  @doc """
  The RFC 8628 `grant_type` a poll must send.
  """
  def grant_type, do: @grant_type

  @doc """
  Human-readable text for an error atom returned by this module.
  """
  def error_description(reason) when is_atom(reason) do
    Map.get(@descriptions, reason, "The device authorization request failed.")
  end

  @doc """
  RFC 8628 JSON body for a device authorization response.

  `{:ok, map}` uses the string keys `device_code`, `user_code`,
  `verification_uri`, `expires_in`, and `interval`.
  `verification_uri_complete` is included when configured.
  `{:error, atom}` uses `error` and `error_description`.
  """
  def code_body({:ok, result}) do
    %{
      "device_code" => result.device_code,
      "user_code" => result.user_code,
      "verification_uri" => result.verification_uri,
      "expires_in" => result.expires_in,
      "interval" => result.interval
    }
    |> maybe_put("verification_uri_complete", Map.get(result, :verification_uri_complete))
  end

  def code_body({:error, reason}) when is_atom(reason), do: error_body(reason)

  @doc """
  RFC 8628 JSON body for a token response.

  Success includes `access_token` and `token_type`. `expires_in` is included
  when the API key expires, and `scope` when the grant had one.
  The API key id stays on the Elixir result (`:api_key_id`) and is left out
  of this body. Errors use `error` and `error_description`.
  """
  def token_body({:ok, result}) do
    %{"access_token" => result.access_token, "token_type" => result.token_type}
    |> maybe_put("expires_in", result.expires_in)
    |> maybe_put("scope", result.scope)
  end

  def token_body({:error, reason}) when is_atom(reason), do: error_body(reason)

  @doc """
  RFC 8628 error object for `reason`.
  """
  def error_body(reason) when is_atom(reason) do
    %{"error" => Atom.to_string(reason), "error_description" => error_description(reason)}
  end

  @doc """
  Headers that present the issued API key to `AuthKit.Auth.Bearer`.

  Either header is enough. The value is the plaintext key.
  """
  def credential_headers(%{access_token: token}) when is_binary(token) do
    %{"authorization" => "Bearer " <> token, "x-api-key" => token}
  end

  @doc """
  Issues a device code and a user code.

  Returns `{:ok, grant}` with `:device_code`, `:user_code`,
  `:verification_uri`, `:verification_uri_complete` (unless disabled),
  `:expires_in` (seconds), and `:interval` (seconds). The plaintext codes
  are only in this return value.

  ## Options

    * `:client_id` — required client identifier, stored for the approval page
    * `:scope` — optional space-separated scope, shown on the approval page
    * `:user_id` — pre-bind the grant so only that user can approve or deny it
  """
  def request_device_authorization(opts \\ [])

  def request_device_authorization(opts) when is_list(opts) do
    ensure_fields!()
    _ = delete_expired_device_codes()

    with :ok <- validate_client(Keyword.get(opts, :client_id)),
         {:ok, scope} <- normalize_scope(Keyword.get(opts, :scope)),
         {:ok, user_id} <- resolve_prebind(opts) do
      issue_codes(opts[:client_id], scope, user_id, @max_attempts)
    end
  end

  def request_device_authorization(_opts), do: {:error, :invalid_request}

  @doc """
  Loads a grant by user code for the signed-in approval page.

  Returns `{:ok, view}` with `:client_id`, `:scope`, `:status`,
  `:expires_in`, and `:interval`. Does not approve the grant.
  An unknown code is `:invalid_grant`. An expired code is `:expired_token`
  and the row is deleted. A code pre-bound to someone else is `:access_denied`.
  """
  def get_device_authorization(user, user_code) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, canonical} <- normalize_user_code(user_code),
         token when not is_nil(token) <- fetch_user_code(canonical) do
      show_loaded(token, user)
    else
      nil -> {:error, :invalid_grant}
      :error -> {:error, :invalid_grant}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Binds `user_code` to `user` and marks the grant approved.

  `user_code` is the code the device displayed. Dashes, spaces, and letter
  case are ignored. Pass `tenant_id:` to scope the API key that a later
  poll will issue. The user must already belong to that tenant.

  Returns `{:ok, view}`. Unknown codes are `:invalid_grant`. Expired codes
  are `:expired_token`. A code pre-bound to another user, or already denied,
  is `:access_denied`. Approving again as the same user returns the view.
  """
  def approve_device_authorization(user, user_code, opts \\ [])

  def approve_device_authorization(user, user_code, opts) when is_list(opts) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, canonical} <- normalize_user_code(user_code),
         {:ok, scope} <- resolve_tenant(user, Keyword.get(opts, :tenant_id)),
         token when not is_nil(token) <- fetch_user_code(canonical) do
      approve_loaded(token, user, scope)
    else
      nil -> {:error, :invalid_grant}
      :error -> {:error, :invalid_grant}
      {:error, reason} -> {:error, reason}
    end
  end

  def approve_device_authorization(_user, _user_code, _opts), do: {:error, :invalid_request}

  @doc """
  Marks the grant denied.

  A later poll returns `:access_denied` until the code expires.
  The same user denying twice returns `{:ok, view}`. Another user, when
  the grant is pre-bound or already denied, gets `:access_denied`.
  """
  def deny_device_authorization(user, user_code) do
    ensure_fields!()

    with :ok <- ensure_user(user),
         {:ok, canonical} <- normalize_user_code(user_code),
         token when not is_nil(token) <- fetch_user_code(canonical) do
      deny_loaded(token, user)
    else
      nil -> {:error, :invalid_grant}
      :error -> {:error, :invalid_grant}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Polls `device_code`.

  ## Options

    * `:grant_type` — required, `AuthKit.Device.grant_type/0`
    * `:client_id` — required, the client id from the code request

  Returns `{:error, :authorization_pending}` while the user has not
  approved, `{:error, :slow_down}` when a pending grant is polled before
  `interval` seconds have passed (and the stored interval grows by 5),
  `{:error, :expired_token}`, `{:error, :access_denied}`, or
  `{:error, :invalid_grant}`.

  `{:ok, token}` includes `:access_token` (the API key, once),
  `:token_type` (`"Bearer"`), `:expires_in` (seconds, or nil when the key
  does not expire), `:scope`, and `:api_key_id`. The device row is deleted
  in the same transaction as the key insert, so a second poll cannot mint
  another key.

  `slow_down` applies while the grant is pending. An approved grant is
  exchanged on the next poll, including one that arrives inside the interval.
  """
  def poll_device_token(device_code, opts \\ [])

  def poll_device_token(device_code, opts) when is_binary(device_code) and is_list(opts) do
    ensure_fields!()

    with :ok <- validate_grant_type(Keyword.get(opts, :grant_type)),
         :ok <- validate_poll_client(Keyword.get(opts, :client_id)) do
      result =
        case fetch_device(device_code) do
          nil -> {:error, :invalid_grant}
          token -> poll_loaded(token, opts[:client_id], DateTime.utc_now(), 0)
        end

      _ = delete_expired_device_codes()
      result
    end
  end

  def poll_device_token(_device_code, _opts), do: {:error, :invalid_request}

  @doc """
  Deletes device grants whose `expires_at` is in the past.

  Returns `{:ok, count}`. Request and poll share a 10 second cooldown.
  Pass `force: true` to ignore it. API keys and sessions are not deleted.
  A poll of one expired code deletes that row itself, so two polls cannot
  raise `Ecto.StaleEntryError`.
  """
  def delete_expired_device_codes(opts \\ []) when is_list(opts) do
    ensure_fields!()

    if Keyword.get(opts, :force, false) or sweep_due?() do
      now = DateTime.utc_now()

      {count, _} =
        from(t in schema(),
          where: t.context == ^@context and not is_nil(t.expires_at) and t.expires_at <= ^now
        )
        |> Repo.delete_all()

      :persistent_term.put(sweep_key(), System.monotonic_time(:millisecond))
      {:ok, count}
    else
      {:ok, 0}
    end
  end

  defp issue_codes(client_id, scope, user_id, attempts) do
    device_code = new_device_code()
    canonical = random_chars(user_code_length())
    user_code = format_user_code(canonical)
    expires = expires_in()
    interval = interval()
    now = DateTime.utc_now()

    attrs = %{
      token: hash(device_code),
      user_code: hash(canonical),
      context: @context,
      status: "pending",
      interval: interval,
      expires_at: DateTime.add(now, expires, :second),
      user_id: user_id,
      name: client_id,
      sent_to: scope,
      updated_at: now,
      tenant_scoped: false
    }

    case insert_grant(attrs) do
      {:ok, _token} ->
        {:ok, code_result(device_code, user_code, expires, interval)}

      {:error, :conflict} when attempts > 1 ->
        issue_codes(client_id, scope, user_id, attempts - 1)

      {:error, :conflict} ->
        {:error, :server_error}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp insert_grant(attrs) do
    changeset =
      schema()
      |> struct()
      |> change(attrs)
      |> unique_constraint(:token, name: :users_tokens_context_token_index)
      |> unique_constraint(:user_code, name: :users_tokens_user_code_index)

    try do
      case Repo.insert(changeset) do
        {:ok, token} ->
          {:ok, token}

        {:error, changeset} ->
          if conflict?(changeset), do: {:error, :conflict}, else: {:error, changeset}
      end
    rescue
      Ecto.ConstraintError -> {:error, :conflict}
    end
  end

  defp conflict?(changeset) do
    Enum.any?(changeset.errors, fn
      {_field, {_msg, opts}} -> opts[:constraint] == :unique
      _other -> false
    end)
  end

  defp show_loaded(token, user) do
    now = DateTime.utc_now()

    cond do
      expired?(token, now) -> expire_row(token)
      bound_to_other?(token, user) -> {:error, :access_denied}
      token.status == "denied" -> {:error, :access_denied}
      true -> {:ok, approval_view(token)}
    end
  end

  defp approve_loaded(token, user, scope) do
    now = DateTime.utc_now()

    cond do
      expired?(token, now) ->
        expire_row(token)

      token.status == "approved" and token.user_id == user.id ->
        {:ok, approval_view(token)}

      token.status == "approved" ->
        {:error, :access_denied}

      token.status == "denied" ->
        {:error, :access_denied}

      bound_to_other?(token, user) ->
        {:error, :access_denied}

      token.status == "pending" ->
        write_approval(token, user, scope, now)

      true ->
        {:error, :invalid_grant}
    end
  end

  defp write_approval(token, user, scope, now) do
    tenant_id = scope && scope.tenant_id
    sets = approval_sets(user, tenant_id, now)

    {count, _} =
      from(t in schema(),
        where:
          t.id == ^token.id and t.context == ^@context and t.status == "pending" and
            t.expires_at > ^now and (is_nil(t.user_id) or t.user_id == ^user.id)
      )
      |> Repo.update_all(set: sets)

    if count == 1 do
      {:ok, approval_view(approved_token(token, user, tenant_id))}
    else
      case refetch(token.id) do
        nil ->
          {:error, :expired_token}

        fresh ->
          if fresh.status == "pending" and not expired?(fresh, DateTime.utc_now()) do
            {:error, :invalid_grant}
          else
            approve_loaded(fresh, user, scope)
          end
      end
    end
  end

  defp approval_sets(user, nil, now) do
    [status: "approved", user_id: user.id, updated_at: now, tenant_scoped: false]
  end

  defp approval_sets(user, tenant_id, now) do
    [
      status: "approved",
      user_id: user.id,
      updated_at: now,
      tenant_scoped: true,
      active_tenant_id: tenant_id
    ]
  end

  defp approved_token(token, user, tenant_id) do
    token = %{token | status: "approved", user_id: user.id, tenant_scoped: not is_nil(tenant_id)}

    if tenant_id && Map.has_key?(token, :active_tenant_id) do
      %{token | active_tenant_id: tenant_id}
    else
      token
    end
  end

  defp deny_loaded(token, user) do
    now = DateTime.utc_now()

    cond do
      expired?(token, now) ->
        expire_row(token)

      token.status == "denied" and (is_nil(token.user_id) or token.user_id == user.id) ->
        {:ok, approval_view(token)}

      token.status == "denied" ->
        {:error, :access_denied}

      token.status == "approved" ->
        {:error, :invalid_grant}

      bound_to_other?(token, user) ->
        {:error, :access_denied}

      token.status == "pending" ->
        write_denial(token, user, now)

      true ->
        {:error, :invalid_grant}
    end
  end

  defp write_denial(token, user, now) do
    {count, _} =
      from(t in schema(),
        where:
          t.id == ^token.id and t.context == ^@context and t.status == "pending" and
            t.expires_at > ^now and (is_nil(t.user_id) or t.user_id == ^user.id)
      )
      |> Repo.update_all(set: [status: "denied", user_id: user.id, updated_at: now])

    if count == 1 do
      {:ok, approval_view(%{token | status: "denied", user_id: user.id})}
    else
      case refetch(token.id) do
        nil ->
          {:error, :expired_token}

        fresh ->
          if fresh.status == "pending" and not expired?(fresh, DateTime.utc_now()) do
            {:error, :invalid_grant}
          else
            deny_loaded(fresh, user)
          end
      end
    end
  end

  defp poll_loaded(token, client_id, now, depth) do
    cond do
      depth > 2 ->
        {:error, :invalid_grant}

      not client_match?(token.name, client_id) ->
        {:error, :invalid_grant}

      expired?(token, now) ->
        expire_row(token)

      token.status == "denied" ->
        {:error, :access_denied}

      token.status == "approved" ->
        issue_credential(token)

      token.status == "pending" ->
        poll_pending(token, client_id, now, depth)

      true ->
        {:error, :invalid_grant}
    end
  end

  defp poll_pending(token, client_id, now, depth) do
    if poll_allowed?(token, now) do
      case claim_poll(token, now) do
        {1, _} ->
          {:error, :authorization_pending}

        {0, _} ->
          case refetch(token.id) do
            nil -> {:error, :invalid_grant}
            fresh -> poll_loaded(fresh, client_id, DateTime.utc_now(), depth + 1)
          end
      end
    else
      _ = bump_interval(token)
      {:error, :slow_down}
    end
  end

  defp poll_allowed?(%{last_request: nil}, _now), do: true

  defp poll_allowed?(%{last_request: last, interval: interval}, now) do
    spacing = if is_integer(interval) and interval >= 1, do: interval, else: @default_interval
    DateTime.compare(now, DateTime.add(last, spacing, :second)) != :lt
  end

  # One writer wins. The WHERE clause is the lock: a second poll sees the
  # new last_request and does not take the slot. delete/update use
  # update_all, never delete!/update!, so a lost race is a count of 0.
  defp claim_poll(token, now) do
    query =
      from t in schema(),
        where: t.id == ^token.id and t.context == ^@context and t.status == "pending"

    query =
      case token.last_request do
        nil ->
          from t in query, where: is_nil(t.last_request)

        last ->
          from t in query,
            where: t.last_request <= ^last and t.interval == ^token.interval
      end

    Repo.update_all(query, set: [last_request: now, updated_at: now])
  end

  defp bump_interval(%{interval: interval})
       when is_integer(interval) and interval >= @max_interval do
    :ok
  end

  defp bump_interval(token) do
    from(t in schema(),
      where:
        t.id == ^token.id and t.context == ^@context and t.status == "pending" and
          t.interval == ^token.interval and t.interval < @max_interval
    )
    |> Repo.update_all(inc: [interval: @interval_step], set: [updated_at: DateTime.utc_now()])

    :ok
  end

  defp issue_credential(token) do
    if Map.get(token, :tenant_scoped) == true and is_nil(Map.get(token, :active_tenant_id)) do
      refuse_scoped(token)
    else
      case Repo.transaction(fn -> issue_in_txn(token) end) do
        {:ok, api_key} -> {:ok, token_success(api_key, token)}
        {:error, reason} -> {:error, normalize_issue_error(reason)}
      end
    end
  end

  defp issue_in_txn(token) do
    {count, _} =
      from(t in schema(),
        where: t.id == ^token.id and t.context == ^@context and t.status == "approved"
      )
      |> Repo.delete_all()

    if count != 1, do: Repo.rollback(:invalid_grant)

    user = Repo.get(Config.user_schema(), token.user_id) || Repo.rollback(:access_denied)

    case ApiKey.create_api_key(user, credential_opts(token)) do
      {:ok, api_key} -> api_key
      {:error, reason} -> Repo.rollback(normalize_issue_error(reason))
    end
  end

  defp refuse_scoped(token) do
    {count, _} =
      from(t in schema(),
        where: t.id == ^token.id and t.status == "approved" and t.context == ^@context
      )
      |> Repo.delete_all()

    if count == 1, do: {:error, :access_denied}, else: {:error, :invalid_grant}
  end

  defp credential_opts(token) do
    []
    |> Keyword.put(:name, key_name(token))
    |> maybe_opt(:prefix, conf(:api_key_prefix, :unset))
    |> maybe_opt(:expires_in, conf(:api_key_expires_in, :unset))
    |> maybe_tenant(token)
  end

  defp key_name(token) do
    case conf(:api_key_name, nil) do
      name when is_binary(name) and name != "" -> name
      _other -> fallback_name(token.name)
    end
  end

  defp fallback_name(client_id) when is_binary(client_id) do
    max = api_name_max()
    if String.length(client_id) in 1..max, do: client_id, else: "cli"
  end

  defp fallback_name(_client_id), do: "cli"

  defp api_name_max do
    :auth_kit
    |> Application.get_env(:api_key, [])
    |> Keyword.get(:maximum_name_length, 32)
  end

  defp maybe_opt(opts, _key, :unset), do: opts
  defp maybe_opt(opts, _key, nil), do: opts
  defp maybe_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp maybe_tenant(opts, token) do
    case Map.get(token, :active_tenant_id) do
      nil -> opts
      id -> Keyword.put(opts, :tenant_id, id)
    end
  end

  defp token_success(api_key, device) do
    %{
      access_token: api_key.key,
      token_type: "Bearer",
      expires_in: remaining_seconds(api_key.expires_at),
      scope: device.sent_to,
      api_key_id: api_key.id
    }
  end

  defp normalize_issue_error(reason) when reason in [:not_a_member, :not_found, :invalid_user],
    do: :access_denied

  defp normalize_issue_error(reason) when is_atom(reason), do: reason
  defp normalize_issue_error(_reason), do: :server_error

  defp expire_row(token) do
    from(t in schema(), where: t.id == ^token.id and t.context == ^@context)
    |> Repo.delete_all()

    {:error, :expired_token}
  end

  defp expired?(%{expires_at: %DateTime{} = at}, now), do: DateTime.compare(now, at) != :lt
  defp expired?(_token, _now), do: true

  defp remaining_seconds(nil), do: nil

  defp remaining_seconds(%DateTime{} = at) do
    max(DateTime.diff(at, DateTime.utc_now(), :second), 0)
  end

  defp approval_view(token) do
    %{
      status: token.status,
      client_id: token.name,
      scope: token.sent_to,
      expires_in: remaining_seconds(token.expires_at),
      interval: token.interval,
      user_id: token.user_id,
      active_tenant_id: Map.get(token, :active_tenant_id)
    }
  end

  defp bound_to_other?(%{user_id: nil}, _user), do: false
  defp bound_to_other?(%{user_id: id}, %{id: id}), do: false
  defp bound_to_other?(%{user_id: _id}, _user), do: true

  defp fetch_device(plaintext) when plaintext == "", do: nil

  defp fetch_device(plaintext) do
    hashed = hash(plaintext)

    token =
      Repo.one(from t in schema(), where: t.token == ^hashed and t.context == ^@context)

    confirm_hash(token, :token, hashed)
  end

  defp fetch_user_code(canonical) do
    hashed = hash(canonical)

    token =
      Repo.one(from t in schema(), where: t.user_code == ^hashed and t.context == ^@context)

    confirm_hash(token, :user_code, hashed)
  end

  defp confirm_hash(nil, _field, hashed) do
    _ = secure_equal?(hashed, @dummy_hash)
    nil
  end

  defp confirm_hash(token, field, hashed) do
    stored = Map.get(token, field)
    if is_binary(stored) and secure_equal?(stored, hashed), do: token, else: nil
  end

  defp refetch(id), do: Repo.get(schema(), id)

  defp code_result(device_code, user_code, expires, interval) do
    uri = verification_uri()

    %{
      device_code: device_code,
      user_code: user_code,
      verification_uri: uri,
      expires_in: expires,
      interval: interval
    }
    |> maybe_complete(uri, user_code)
  end

  defp maybe_complete(result, uri, user_code) do
    if conf(:verification_uri_complete, true) do
      Map.put(result, :verification_uri_complete, complete_uri(uri, user_code))
    else
      result
    end
  end

  defp complete_uri(uri, user_code) do
    separator = if String.contains?(uri, "?"), do: "&", else: "?"
    uri <> separator <> "user_code=" <> URI.encode_www_form(user_code)
  end

  defp validate_grant_type(@grant_type), do: :ok
  defp validate_grant_type(nil), do: {:error, :invalid_request}
  defp validate_grant_type(_grant_type), do: {:error, :unsupported_grant_type}

  defp validate_poll_client(client_id) do
    cond do
      not valid_client_id?(client_id) -> {:error, :invalid_request}
      not client_allowed?(client_id) -> {:error, :invalid_client}
      true -> :ok
    end
  end

  defp validate_client(client_id) do
    cond do
      not valid_client_id?(client_id) -> {:error, :invalid_request}
      not client_allowed?(client_id) -> {:error, :invalid_client}
      true -> :ok
    end
  end

  defp valid_client_id?(id) when is_binary(id) do
    length = String.length(id)

    length in 1..@max_client_id and String.printable?(id) and
      not Regex.match?(~r/\s/, id)
  end

  defp valid_client_id?(_id), do: false

  defp client_allowed?(client_id) do
    case conf(:allowed_clients, nil) do
      nil -> true
      fun when is_function(fun, 1) -> fun.(client_id) == true
      list when is_list(list) -> client_id in list
      _other -> false
    end
  end

  defp client_match?(stored, given) when is_binary(stored) and is_binary(given) do
    if byte_size(stored) == byte_size(given) do
      secure_equal?(stored, given)
    else
      false
    end
  end

  defp client_match?(_stored, _given), do: false

  defp normalize_scope(nil), do: {:ok, nil}
  defp normalize_scope(""), do: {:ok, nil}

  defp normalize_scope(scope) when is_binary(scope) do
    scope = String.trim(scope)

    cond do
      scope == "" -> {:ok, nil}
      String.length(scope) > @max_scope -> {:error, :invalid_request}
      not String.printable?(scope) -> {:error, :invalid_request}
      true -> {:ok, scope}
    end
  end

  defp normalize_scope(_scope), do: {:error, :invalid_request}

  defp resolve_prebind(opts) do
    case Keyword.get(opts, :user_id) do
      nil ->
        {:ok, nil}

      id ->
        with {:ok, id} <- cast_id(Config.user_schema(), id),
             %{} = user <- Repo.get(Config.user_schema(), id) do
          {:ok, user.id}
        else
          _other -> {:error, :invalid_user}
        end
    end
  end

  defp resolve_tenant(_user, nil), do: {:ok, nil}

  defp resolve_tenant(user, tenant_id) do
    ensure_tenant_field!()

    with {:ok, tenant} <- fetch_tenant(tenant_id),
         {:ok, _member} <- fetch_member(user, tenant.id) do
      {:ok, %{tenant_id: tenant.id}}
    end
  end

  defp fetch_tenant(id) do
    with {:ok, id} <- cast_id(Config.tenant_schema(), id) do
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
      Scoped device approval needs auth_kit_active_tenant_field/0 on the user token schema.
      """
    end
  end

  defp ensure_user(%{id: id} = user) when not is_nil(id) do
    if is_struct(user, Config.user_schema()) and
         match?({:ok, _}, cast_id(Config.user_schema(), id)) do
      :ok
    else
      {:error, :invalid_user}
    end
  end

  defp ensure_user(_user), do: {:error, :invalid_user}

  defp cast_id(schema, id), do: Ecto.Type.cast(schema.__schema__(:type, :id), id)

  defp new_device_code do
    Base.url_encode64(:crypto.strong_rand_bytes(@device_bytes), padding: false)
  end

  defp format_user_code(canonical) do
    canonical
    |> String.graphemes()
    |> Enum.chunk_every(4)
    |> Enum.map_join("-", &Enum.join/1)
  end

  defp normalize_user_code(code) when is_binary(code) do
    allowed = MapSet.new(alphabet_chars())

    normalized =
      code
      |> String.upcase()
      |> String.graphemes()
      |> Enum.filter(&MapSet.member?(allowed, &1))
      |> IO.iodata_to_binary()

    if String.length(normalized) in 4..32, do: {:ok, normalized}, else: :error
  end

  defp normalize_user_code(_code), do: :error

  defp random_chars(count), do: random_chars(count, [])

  defp random_chars(0, acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp random_chars(count, acc) do
    # 32 symbols divide 256, so the low bits are unbiased.
    <<byte>> = :crypto.strong_rand_bytes(1)
    random_chars(count - 1, [Enum.at(alphabet_chars(), rem(byte, 32)) | acc])
  end

  defp alphabet_chars, do: String.graphemes(@alphabet)

  defp hash(value), do: :crypto.hash(:sha256, value)

  defp secure_equal?(left, right), do: Plug.Crypto.secure_compare(left, right)

  defp expires_in do
    case conf(:expires_in, @default_expires_in) do
      seconds when is_integer(seconds) and seconds > 0 -> seconds
      _other -> @default_expires_in
    end
  end

  defp interval do
    case conf(:interval, @default_interval) do
      seconds when is_integer(seconds) and seconds >= 1 -> seconds
      _other -> @default_interval
    end
  end

  defp user_code_length do
    case conf(:user_code_length, @default_user_code_length) do
      length when is_integer(length) and length in 4..32 -> length
      _other -> @default_user_code_length
    end
  end

  defp verification_uri do
    case conf(:verification_uri, "/device") do
      uri when is_binary(uri) and uri != "" -> uri
      _other -> "/device"
    end
  end

  defp conf(key, default) do
    :auth_kit
    |> Application.get_env(:device_authorization, [])
    |> Keyword.get(key, default)
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp sweep_due? do
    now = System.monotonic_time(:millisecond)

    case :persistent_term.get(sweep_key(), nil) do
      nil -> true
      last -> now - last >= @sweep_cooldown_ms
    end
  end

  defp sweep_key, do: {__MODULE__, :last_expired_sweep}

  defp ensure_fields! do
    missing = (@device_fields ++ @reused_fields) -- schema().__schema__(:fields)

    if missing != [] do
      raise ArgumentError, """
      Device authorization needs auth_kit_device_fields/0 and auth_kit_api_key_fields/0
      on the user token schema.
      Missing fields: #{inspect(missing)}

      Add the columns in docs/device_flow.md, then:

          schema "users_tokens" do
            auth_kit_user_token_fields()
            auth_kit_api_key_fields()
            auth_kit_device_fields()
          end
      """
    end
  end

  defp schema, do: Config.user_token_schema()
end
