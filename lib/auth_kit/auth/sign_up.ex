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
  @spec sign_up_email(Conn.t(), signup_params()) :: {:ok, user()} | {:error, signup_error()}
  def sign_up_email(conn, params) do
    types = %{
      email: :string,
      name: :string,
      password: :string,
      avatar_url: :string,
      callback_url: :string
    }

    params =
      case Params.validate(params, types, [:email, :password], fn changeset ->
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

    if Auth.fetch_user_by_email(email) do
      Logger.info("Sign-up attempt for existing email: #{email}")
      throw({:error, HttpError.new(:unprocessable_entity, "User already exists")})
    end

    user = Auth.create_user(%{email: String.downcase(email), name: name, avatar_url: avatar_url})

    _account =
      Auth.link_identity(%{
        user_id: user.id,
        provider: "credential",
        identity: user.id,
        password: password
      })

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

  defp signed_in_path(_conn), do: "/"
end
