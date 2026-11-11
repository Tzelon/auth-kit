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

  require Logger

  alias AuthKit.OAuth.{Error, HTTP, IDToken, PKCE}

  @authorize_url "https://accounts.google.com/o/oauth2/v2/auth"
  @token_url "https://oauth2.googleapis.com/token"
  @jwks_url "https://www.googleapis.com/oauth2/v3/certs"
  @default_scope "openid email profile"

  @doc """
  Builds the Google authorization URL.

  Returns the session params that must be stored whole and passed back to
  `callback/2` as `:session_params`. They include the PKCE verifier and the
  time the state was issued. A session older than `:oauth_state_ttl` seconds
  (default 600) is rejected.
  """
  def authorize_url(config) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      state = random_token()
      nonce = random_token()
      pkce = PKCE.generate()

      query =
        [scope: @default_scope]
        |> Keyword.merge(Keyword.get(config, :authorization_params, []))
        |> Keyword.merge(
          response_type: "code",
          client_id: client_id,
          redirect_uri: redirect_uri,
          state: state,
          nonce: nonce,
          code_challenge: pkce.code_challenge,
          code_challenge_method: pkce.code_challenge_method
        )
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)

      {:ok,
       %{
         url: @authorize_url <> "?" <> URI.encode_query(query),
         session_params: %{
           state: state,
           nonce: nonce,
           code_verifier: pkce.code_verifier,
           issued_at: System.system_time(:second)
         }
       }}
    end
  end

  @doc """
  Exchanges the callback code for tokens and returns the user claims.
  """
  def callback(config, params) do
    with {:ok, session_params} <- fetch_config(config, :session_params),
         :ok <- check_error(params),
         {:ok, verifier} <- PKCE.check(params, session_params),
         {:ok, code} <- fetch_param(params, "code"),
         {:ok, token} <- fetch_token(config, code, verifier),
         {:ok, user} <- verify_id_token(config, token, session_params) do
      {:ok, %{user: user, token: token}}
    end
  end

  defp check_error(%{"error" => error} = params) do
    {:error,
     Error.exception(message: "Google returned an error: #{params["error_description"] || error}")}
  end

  defp check_error(_params), do: :ok

  defp fetch_token(config, code, verifier) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, client_secret} <- fetch_config(config, :client_secret),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      case HTTP.post_form(@token_url, %{
             grant_type: "authorization_code",
             code: code,
             client_id: client_id,
             client_secret: client_secret,
             redirect_uri: redirect_uri,
             code_verifier: verifier
           }) do
        {:ok, 200, %{"id_token" => _} = token} ->
          {:ok, token}

        {:ok, status, body} ->
          log_token_failure(status, body)
          {:error, Error.exception(message: "Token request failed with status #{status}")}

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp log_token_failure(status, body) do
    Logger.error(
      "Google request failed status=#{status} error=#{token_field(body, "error")} error_description=#{token_field(body, "error_description")}"
    )
  end

  defp token_field(body, key) when is_map(body), do: body[key]
  defp token_field(_body, _key), do: nil

  defp verify_id_token(config, %{"id_token" => id_token}, session_params) do
    nonce = session_params[:nonce] || session_params["nonce"]
    IDToken.verify(id_token, @jwks_url, config[:client_id], nonce)
  end

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
