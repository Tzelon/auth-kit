defmodule AuthKit.Auth.SignIn do
  require Logger

  import AuthKit.Auth.ConnHelpers
  import Plug.Conn

  alias AuthKit.Auth
  alias AuthKit.Auth.HttpError
  alias AuthKit.Auth.Params

  @typedoc """
  Represents user credentials and options, typically for authentication or registration.

  Keys:
  - `:email` (required): Email of the user.
  - `:password` (required): Password of the user.
  - `:callback_url` (optional): Callback URL to use as a redirect for email verification.
  - `:remember_me` (optional): If this is false, the session will not be remembered. Defaults to `true` at runtime (Note: typespecs don't enforce defaults).
  """
  @type email_params :: %{
          required(:email) => String.t(),
          required(:password) => String.t(),
          optional(:callback_url) => String.t(),
          optional(:remember_me) => boolean()
        }

  def sign_in_email(conn, params) do
    types = %{email: :string, password: :string, remember_me: :boolean}

    %{"email" => email, "password" => password} =
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

    user = Auth.fetch_user_by_email(email, preload: [:identities])

    if user == nil do
      Logger.error("User not found", email: email)
      throw({:error, HttpError.new(:unauthorized, "Invalid email or password")})
    end

    credential_identity = Enum.find(user.identities, &(&1.provider == "credential"))

    if not Auth.valid_password?(credential_identity, password) do
      Logger.error("Invalid password")
      throw({:error, HttpError.new(:unauthorized, "Invalid email or password")})
    end

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
