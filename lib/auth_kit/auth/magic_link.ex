defmodule AuthKit.Auth.MagicLink do
  require Logger

  import AuthKit.Auth.ConnHelpers
  import Plug.Conn

  alias AuthKit.Auth
  alias AuthKit.Auth.HttpError
  alias AuthKit.Auth.Params

  @typedoc """
  Options for configuring magic link authentication.
  """
  @type magic_link_options :: [
          expires_in: non_neg_integer(),
          send_magic_link: send_magic_link_fun(),
          generate_token: generate_token_fun()
        ]

  @typedoc """
  Function that implements sending the magic link.

  Takes a map with email, url, and token, plus an optional request.
  """
  @type send_magic_link_fun ::
          (%{email: String.t(), url: String.t(), token: String.t()}, term() | nil -> any())

  @typedoc """
  Function to generate a token for magic link authentication.

  Takes an email address and returns a token string.
  """
  @type generate_token_fun :: (String.t() -> String.t())

  @typedoc """
  Magic link request payload.

  ## Fields

  * `:email` - Email address to send the magic link (required)
  * `:name` - User display name. Only used if the user is registering for the first time. (optional)
  * `:callback_url` - URL to redirect after magic link verification (optional)
  """
  @type magic_link_params :: %{
          required(:email) => String.t(),
          optional(:name) => String.t(),
          optional(:callback_url) => String.t()
        }

  @spec sign_in(Conn.t(), magic_link_params(), magic_link_options()) :: any()
  def sign_in(conn, params, opts) do
    types = %{email: :string, name: :string, callback_url: :string}

    %{"email" => email, "name" => name} =
      case Params.validate(params, types, [:email], &Params.validate_email_format/1) do
        {:ok, params} ->
          params

        {:error, errors} ->
          throw({:error, HttpError.new(:bad_request, errors)})
      end

    email = String.downcase(email)

    user =
      if user = Auth.fetch_user_by_email(email) do
        user
      else
        Auth.create_user(%{email: email, name: name})
      end

    token = Auth.generate_login_token(user)

    send_magic_link = Keyword.fetch!(opts, :send_magic_link)
    send_magic_link.(token)

    conn |> redirect(to: "/users/log-in")
  end

  @typedoc """
  Magic link verify payload.

  ## Fields

  * `:token` - Verification token (required)
  * `:callback_url` - URL to redirect after magic link verification, if not provided will return session (optional)
  """
  @type magic_link_verify_params :: %{
          required(:email) => String.t(),
          optional(:name) => String.t(),
          optional(:callback_url) => String.t()
        }

  @spec verify(Conn.t(), magic_link_verify_params()) :: any()
  def verify(conn, params) do
    types = %{token: :string, callback_url: :string}

    %{"token" => token, "callback_url" => callback_url} =
      case Params.validate(params, types, [:token]) do
        {:ok, params} ->
          params

        {:error, errors} ->
          throw({:error, HttpError.new(:bad_request, errors)})
      end

    user =
      case Auth.verify_login_token(token) do
        {:ok, user, _} ->
          user

        {:error, _error} ->
          throw({:error, conn |> redirect(to: "#{callback_url}?error=INVALID_TOKEN")})
      end

    token = Auth.generate_session_token(user)
    user_return_to = get_session(conn, :user_return_to)

    conn
    |> renew_session()
    |> put_token_in_session(token)
    |> maybe_write_remember_me_cookie(token, params)
    |> redirect(to: user_return_to || signed_in_path(conn))
  catch
    {:error, conn} ->
      conn
  end

  defp signed_in_path(_conn), do: "/"
end
