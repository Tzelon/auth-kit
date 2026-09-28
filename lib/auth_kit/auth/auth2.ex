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
      config
      |> update_in([:authorization_params, :prompt], fn _ ->
        if params["request_sign_up"], do: "consent", else: "select_account"
      end)
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
    types = %{provider: :string, code: :string, state: :string}

    with {:ok, params} <- validate_params(params, types, [:provider, :code]),
         {:ok, strategy, config} <- get_provider(params["provider"]) do
      # End-user will return to the callback URL with params attached to the
      # request. These must be passed on to the strategy. In this example we only
      # expect GET query params, but the provider could also return the user with
      # a POST request where the params is in the POST body.
      %{params: params} = fetch_query_params(conn)

      # The session params (used for OAuth 2.0 and OIDC strategies) stored in the
      # request phase will be used in the callback phase
      session_params = get_session(conn, :session_params)

      config
      # Session params should be added to the config so the strategy can use them
      |> Keyword.put(:session_params, session_params)
      |> strategy.callback(params)
      |> case do
        {:ok, %{user: user, token: token}} ->
          {:ok, dbuser} = find_or_maybe_create_user(params["provider"], user, opts)

          expires_at =
            DateTime.add(DateTime.utc_now(), token["expires_in"], :second)

          _account =
            Auth.update_user_tokens(dbuser, %{
              provider: params["provider"],
              identity: user["sub"],
              access_token: token["access_token"],
              refresh_token: token["refresh_token"],
              access_token_expires_at: expires_at,
              scope: token["scope"],
              id_token: token["id_token"]
            })

          # TODO:  how should I link user if if have whatsapp login already?

          token = Auth.generate_session_token(dbuser)
          user_return_to = get_session(conn, :user_return_to)

          conn
          |> renew_session()
          |> put_token_in_session(token)
          |> maybe_write_remember_me_cookie(token, params)
          |> redirect(to: user_return_to || "/")

        {:error, error} ->
          raise error
      end
    end
  end

  # Get the OAuth provider module based on the provider name
  @spec get_provider(String.t()) :: {:ok, module()} | {:error, :invalid_provider, map()}
  defp get_provider(provider) do
    case provider do
      "google" -> {:ok, AuthKit.OAuth.Google, Application.fetch_env!(:auth_kit, :google)}
      # Add other providers as needed
      _ -> {:error, :invalid_provider, %{provider: "Invalid provider specified"}}
    end
  end

  # The provider has verified the email, which proves the user owns it. An
  # existing account with that email gets confirmed, which also removes any
  # password set on it before the email was proven.
  defp find_or_maybe_create_user(provider, params, opts) do
    cond do
      user = Auth.fetch_user_by_identity(provider, params["sub"]) ->
        {:ok, user}

      user = Auth.fetch_user_by_email(params["email"]) ->
        confirm_user_email(user)

      not Keyword.get(opts, :auto_signup, false) ->
        {:error, :user_not_found}

      Keyword.get(opts, :auto_signup) ->
        %{
          email: String.downcase(params["email"]),
          name: params["name"],
          avatar_url: params["picture"]
        }
        |> Auth.create_user(opts)
        |> confirm_user_email()
    end
  end

  defp confirm_user_email(user) do
    with {:ok, user, _expired_tokens} <- Auth.confirm_user_email(user) do
      {:ok, user}
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
