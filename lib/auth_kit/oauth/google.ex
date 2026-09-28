defmodule AuthKit.OAuth.Google do
  @moduledoc """
  Google sign-in using OpenID Connect.

  Follows the same interface as `Assent.Strategy.Google`: `authorize_url/1`
  starts the flow and `callback/2` finishes it.

  ## Config

    * `:client_id` - OAuth client ID (required)
    * `:client_secret` - OAuth client secret (required)
    * `:redirect_uri` - Callback URL registered with Google (required)
    * `:authorization_params` - Extra params for the authorization URL (optional)
    * `:session_params` - Params stored by `authorize_url/1`, required by `callback/2`
  """

  alias AuthKit.OAuth.{Error, HTTP}

  @authorize_url "https://accounts.google.com/o/oauth2/v2/auth"
  @token_url "https://oauth2.googleapis.com/token"
  @issuers ["https://accounts.google.com", "accounts.google.com"]
  @default_scope "openid email profile"

  @doc """
  Builds the Google authorization URL.

  Returns the session params that must be stored and passed back to
  `callback/2` as the `:session_params` config.
  """
  def authorize_url(config) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      state = random_token()
      nonce = random_token()

      query =
        [scope: @default_scope]
        |> Keyword.merge(Keyword.get(config, :authorization_params, []))
        |> Keyword.merge(
          response_type: "code",
          client_id: client_id,
          redirect_uri: redirect_uri,
          state: state,
          nonce: nonce
        )
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)

      {:ok,
       %{
         url: @authorize_url <> "?" <> URI.encode_query(query),
         session_params: %{state: state, nonce: nonce}
       }}
    end
  end

  @doc """
  Exchanges the callback code for tokens and returns the user claims.
  """
  def callback(config, params) do
    with {:ok, session_params} <- fetch_config(config, :session_params),
         :ok <- check_error(params),
         :ok <- check_state(params, session_params),
         {:ok, code} <- fetch_param(params, "code"),
         {:ok, token} <- fetch_token(config, code),
         {:ok, user} <- verify_id_token(config, token, session_params) do
      {:ok, %{user: user, token: token}}
    end
  end

  defp check_error(%{"error" => error} = params) do
    {:error, Error.exception(message: "Google returned an error: #{params["error_description"] || error}")}
  end

  defp check_error(_params), do: :ok

  defp check_state(params, session_params) do
    expected = session_params[:state] || session_params["state"]
    actual = params["state"]

    if is_binary(expected) and is_binary(actual) and byte_size(expected) == byte_size(actual) and
         :crypto.hash_equals(expected, actual) do
      :ok
    else
      {:error, Error.exception(message: "Invalid state param, possible CSRF attempt")}
    end
  end

  defp fetch_token(config, code) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, client_secret} <- fetch_config(config, :client_secret),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      case HTTP.post_form(@token_url, %{
             grant_type: "authorization_code",
             code: code,
             client_id: client_id,
             client_secret: client_secret,
             redirect_uri: redirect_uri
           }) do
        {:ok, 200, %{"id_token" => _} = token} ->
          {:ok, token}

        {:ok, status, body} ->
          {:error, Error.exception(message: "Token request failed with status #{status}: #{inspect(body)}")}

        {:error, error} ->
          {:error, error}
      end
    end
  end

  # The ID token comes straight from Google's token endpoint over a verified
  # TLS connection, so per Google's docs the signature check can be skipped.
  # The claims are still validated.
  defp verify_id_token(config, %{"id_token" => id_token}, session_params) do
    with {:ok, claims} <- decode_jwt_payload(id_token),
         :ok <- check_claim(claims["iss"] in @issuers, "Invalid issuer"),
         :ok <- check_claim(claims["aud"] == config[:client_id], "Invalid audience"),
         :ok <- check_claim(not expired?(claims["exp"]), "ID token has expired"),
         :ok <- check_claim(claims["nonce"] == (session_params[:nonce] || session_params["nonce"]), "Invalid nonce") do
      {:ok, claims}
    end
  end

  defp decode_jwt_payload(jwt) do
    with [_header, payload, _signature] <- String.split(jwt, "."),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} when is_map(claims) <- JSON.decode(json) do
      {:ok, claims}
    else
      _ -> {:error, Error.exception(message: "Invalid ID token")}
    end
  end

  defp expired?(exp) when is_integer(exp), do: exp <= System.system_time(:second)
  defp expired?(_exp), do: true

  defp check_claim(true, _message), do: :ok
  defp check_claim(false, message), do: {:error, Error.exception(message: message)}

  defp fetch_config(config, key) do
    case Keyword.get(config, key) do
      nil -> {:error, Error.exception(message: "Missing #{inspect(key)} in config")}
      value -> {:ok, value}
    end
  end

  defp fetch_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, Error.exception(message: "Missing #{inspect(key)} param")}
    end
  end

  defp random_token do
    32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end
end
