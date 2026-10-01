defmodule AuthKit.Auth.SignUp do
  require Logger

  import AuthKit.Auth.ConnHelpers
  import Plug.Conn

  alias AuthKit.Auth
  alias AuthKit.Auth.HttpError
  alias AuthKit.Auth.Params

  @typedoc """
  The response after a successful user signup.
  """
  @type user :: %{
          id: String.t(),
          name: String.t(),
          email: String.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @typedoc """
  Possible error responses from the signup process.
  """
  @type signup_error ::
          {:validation_error, [String.t()]}
          | {:email_taken, String.t()}
          | {:internal_error, String.t()}

  @typedoc """
  User signup request payload.

  ## Fields

  * `:name` - The name of the user (required)
  * `:email` - The email of the user (required)
  * `:password` - The password of the user (required)
  * `:callback_url` - The URL to use for email verification callback (optional)
  """
  @type signup_params :: %{
          required(:name) => String.t(),
          required(:email) => String.t(),
          required(:password) => String.t(),
          optional(:callback_url) => String.t()
        }

  @doc """
  Sign up a user using email and password.

  Takes a map of signup parameters and creates a new user account.
  Returns the created user or an error tuple.
  """
  @spec sign_up_email(Conn.t(), signup_params(), keyword()) :: Conn.t()
  def sign_up_email(conn, params, opts \\ []) do
    types = %{
      email: :string,
      name: :string,
      password: :string,
      avatar_url: :string,
      callback_url: :string
    }

    params =
      case Params.validate(params, types, [:name, :email, :password], fn changeset ->
             changeset
             |> Params.validate_email_format()
             |> Params.validate_password_length()
           end) do
        {:ok, params} ->
          params

        {:error, errors} ->
          throw({:error, HttpError.new(:bad_request, errors)})
      end

    %{
      "name" => name,
      "email" => email,
      "password" => password,
      "avatar_url" => avatar_url,
      "callback_url" => _callback_url
    } =
      params

    email = String.downcase(email)

    if Auth.fetch_user_by_email(email) do
      Logger.info("Sign-up attempt for existing email: #{email}")
      throw({:error, HttpError.new(:unprocessable_entity, "User already exists")})
    end

    user = Auth.create_user(%{email: email, name: name, avatar_url: avatar_url})

    _account =
      Auth.link_identity(%{
        user_id: user.id,
        provider: "credential",
        identity: user.id,
        password: password
      })

    maybe_send_confirm_email(user, opts)

    token = Auth.generate_session_token(user)
    user_return_to = get_session(conn, :user_return_to)

    conn
    |> renew_session()
    |> put_token_in_session(token)
    |> maybe_write_remember_me_cookie(token, params)
    |> redirect(to: user_return_to || signed_in_path(conn))
  catch
    {:error, error} ->
      raise error
  end

  @doc """
  Confirms the email from a `"confirm"` token sent after password sign-up.

  The caller passes `send_confirm_email: fn token -> ... end` to
  `sign_up_email/3`. Verifying the token calls `Auth.confirm_user_email/1`,
  which removes a password set before the email was proven, then starts a
  new session because that confirmation expires the old one.
  """
  def confirm_email(conn, params) do
    types = %{token: :string}

    %{"token" => token} =
      case Params.validate(params, types, [:token]) do
        {:ok, params} ->
          params

        {:error, errors} ->
          throw({:error, HttpError.new(:bad_request, errors)})
      end

    case Auth.verify_confirm_token(token) do
      {:ok, user, _} ->
        session = Auth.generate_session_token(user)

        conn
        |> renew_session()
        |> put_token_in_session(session)
        |> redirect(to: signed_in_path(conn))

      {:error, _reason} ->
        redirect(conn, to: "/users/log-in?error=INVALID_TOKEN")
    end
  catch
    {:error, error} ->
      raise error
  end

  defp maybe_send_confirm_email(user, opts) do
    if send_confirm_email = Keyword.get(opts, :send_confirm_email) do
      send_confirm_email.(Auth.generate_email_token(user, "confirm"))
    end
  end

  defp signed_in_path(_conn), do: "/"
end
