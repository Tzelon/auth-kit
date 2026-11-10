defmodule AuthKit.Auth.Auth2 do
  require Logger

  import AuthKit.Auth.ConnHelpers
  import Plug.Conn

  alias AuthKit.Auth
  alias AuthKit.Auth.Params

  @doc """
  Social authentication parameters.

  ## Fields

    * `:provider` - OAuth2 provider to use (required)
    * `:request_sign_up` - Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider (optional)

  """
  @type social_auth_params :: %{
          required(:provider) => SocialProvider.t(),
          optional(:request_sign_up) => boolean()
        }

  @spec sign_in_social(Conn.t(), social_auth_params()) :: Conn.t()
  def sign_in_social(conn, params) do
    types = %{provider: :string, request_sign_up: :boolean, login_hint: :string}

    with {:ok, params} <- validate_params(params, types, [:provider]),
         {:ok, strategy, config} <- get_provider(params["provider"]) do
      prompt = if params["request_sign_up"], do: "consent", else: "select_account"

      config
      |> Keyword.put(
        :authorization_params,
        config
        |> Keyword.get(:authorization_params, [])
        |> Keyword.put(:prompt, prompt)
      )
      |> strategy.authorize_url()
      |> case do
        {:ok, %{url: url, session_params: session_params}} ->
          # Session params (used for OAuth 2.0 and OIDC strategies) will be
          # retrieved when user returns for the callback phase
          conn = put_session(conn, :session_params, session_params)

          # Redirect end-user to Github to authorize access to their account
          conn
          |> put_resp_header("location", url)
          |> send_resp(302, "")

        {:error, error} ->
          # Something went wrong generating the request authorization url
          conn
          |> put_resp_content_type("text/plain")
          |> send_resp(
            500,
            "Something went wrong generating the request authorization url: #{inspect(error)}"
          )
      end
    end
  end

  @spec callback(Conn.t(), map(), keyword()) :: Conn.t()
  def callback(conn, params, opts \\ []) do
    session_params = get_session(conn, :session_params)
    conn = delete_session(conn, :session_params)
    types = %{provider: :string, code: :string, state: :string}

    with {:ok, validated} <- validate_params(params, types, [:provider, :code]),
         provider = validated["provider"],
         {:ok, strategy, config} <- get_provider(provider) do
      # Query params carry code and state. They must not replace the validated provider.
      %{params: query_params} = fetch_query_params(conn)

      callback_params =
        validated
        |> Map.merge(query_params)
        |> Map.put("provider", provider)

      # The session params (used for OAuth 2.0 and OIDC strategies) stored in the
      # request phase will be used in the callback phase
      config
      # Session params should be added to the config so the strategy can use them
      |> Keyword.put(:session_params, session_params)
      |> strategy.callback(callback_params)
      |> case do
        {:ok, %{user: user, token: token}} ->
          case Auth.sign_in_with_oauth(
                 provider,
                 oauth_profile(user),
                 oauth_token_attrs(token),
                 opts
               ) do
            {:ok, dbuser} ->
              session_token = Auth.generate_session_token(dbuser)
              user_return_to = get_session(conn, :user_return_to)

              conn
              |> renew_session()
              |> put_token_in_session(session_token)
              |> maybe_write_remember_me_cookie(session_token, callback_params)
              |> redirect(to: user_return_to || "/")

            {:error, reason} ->
              oauth_failure(conn, reason)
          end

        {:error, error} ->
          oauth_failure(conn, error)
      end
    else
      other ->
        oauth_failure(conn, other)
    end
  end

  # Google's email_verified claim may be the string "true".
  def oauth_profile(claims) do
    %{
      identity: claims["sub"],
      email: claims["email"],
      email_verified: claims["email_verified"] in [true, "true"],
      name: claims["name"],
      avatar_url: claims["picture"]
    }
  end

  # GitHub's OAuth app tokens omit expires_in when the token does not expire.
  defp oauth_token_attrs(token) do
    attrs = %{
      access_token: token["access_token"],
      refresh_token: token["refresh_token"],
      scope: token["scope"],
      id_token: token["id_token"]
    }

    case token["expires_in"] do
      seconds when is_integer(seconds) ->
        Map.put(
          attrs,
          :access_token_expires_at,
          DateTime.add(DateTime.utc_now(), seconds, :second)
        )

      _ ->
        attrs
    end
  end

  defp oauth_failure(conn, %Ecto.Changeset{} = changeset) do
    Logger.error("OAuth sign-in failed: #{inspect(changeset.errors)}")
    oauth_failure_response(conn)
  end

  defp oauth_failure(conn, %AuthKit.OAuth.Error{message: message}) do
    Logger.error("OAuth sign-in failed: #{message}")
    oauth_failure_response(conn)
  end

  defp oauth_failure(conn, reason) do
    Logger.error("OAuth sign-in failed: #{inspect(reason)}")
    oauth_failure_response(conn)
  end

  defp oauth_failure_response(conn) do
    conn
    |> delete_session(:session_params)
    |> put_resp_content_type("text/plain")
    |> send_resp(401, "OAuth sign-in failed")
  end

  # Get the OAuth provider module based on the provider name
  @spec get_provider(String.t()) :: {:ok, module()} | {:error, :invalid_provider, map()}
  defp get_provider(provider) do
    case provider do
      "google" -> {:ok, AuthKit.OAuth.Google, Application.fetch_env!(:auth_kit, :google)}
      "github" -> {:ok, AuthKit.OAuth.GitHub, Application.fetch_env!(:auth_kit, :github)}
      _ -> {:error, :invalid_provider, %{provider: "Invalid provider specified"}}
    end
  end

  defp validate_params(params, types, required) do
    case Params.validate(params, types, required) do
      {:ok, params} ->
        {:ok, params}

      {:error, errors} ->
        {:error, :validation_error, errors}
    end
  end
end
