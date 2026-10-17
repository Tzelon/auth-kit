defmodule AuthKit.Auth.Bearer do
  @moduledoc """
  Loads the current user from an API key or a session bearer token.

  Put it in a pipeline:

      plug AuthKit.Auth.Bearer

  `x-api-key` is checked first.
  Change the header with `config :auth_kit, api_key: [api_key_headers: "x-api-key"]`.
  A string or a list of header names is accepted.

  Otherwise `Authorization: Bearer` is a session token from
  `AuthKit.UserToken.encode_session_token/1`, and if that is not a live
  session it is checked as an API key.

  When `x-api-key` is present, a bearer session on the same request is not used.

  Assigns:

    * `:current_user` — the user, or `nil`
    * `:current_api_key` — API key metadata without the secret, or `nil` for a session
    * `:current_tenant_id` — the key's tenant scope, or `nil`
  """

  @behaviour Plug

  import Plug.Conn

  alias AuthKit.ApiKey
  alias AuthKit.Auth
  alias AuthKit.UserToken

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    case authenticate(conn) do
      {:api_key, user, key} ->
        conn
        |> assign(:current_user, user)
        |> assign(:current_api_key, key)
        |> assign(:current_tenant_id, key.active_tenant_id)

      {:user, user} ->
        conn
        |> assign(:current_user, user)
        |> assign(:current_api_key, nil)
        |> assign(:current_tenant_id, nil)

      :none ->
        conn
        |> assign(:current_user, nil)
        |> assign(:current_api_key, nil)
        |> assign(:current_tenant_id, nil)
    end
  end

  defp authenticate(conn) do
    case header_api_key(conn) do
      nil -> bearer(conn)
      key -> api_key(key)
    end
  end

  defp bearer(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> encoded] -> session(encoded) || api_key(encoded)
      _other -> :none
    end
  end

  defp session(encoded) do
    with {:ok, token} <- UserToken.decode_session_token(encoded),
         %{} = user <- Auth.fetch_user_by_session_token(token) do
      {:user, user}
    else
      _other -> nil
    end
  end

  defp api_key(key) do
    case ApiKey.authenticate(key) do
      {:ok, user, metadata} -> {:api_key, user, metadata}
      :error -> :none
    end
  end

  defp header_api_key(conn) do
    :auth_kit
    |> Application.get_env(:api_key, [])
    |> Keyword.get(:api_key_headers, ["x-api-key"])
    |> List.wrap()
    |> Enum.find_value(&header_value(conn, &1))
  end

  defp header_value(conn, header) do
    header = header |> to_string() |> String.downcase()

    case get_req_header(conn, header) do
      [value | _] ->
        value = String.trim(value)
        if value != "", do: value

      _other ->
        nil
    end
  end
end
