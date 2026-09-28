defmodule AuthKit.Auth.Whatsapp do
  require Logger

  import Ecto.Changeset
  import AuthKit.Auth.ConnHelpers
  import Plug.Conn

  alias AuthKit.Repo
  alias AuthKit.Models.UserToken
  alias AuthKit.Auth
  alias AuthKit.Auth.Params

  alias AuthKit.Auth.Whatsapp

  use AuthKit.Schema, prefix: "usr_"

  schema "users" do
    field :phone_number, :string
    field :name, :string
    field :phone_number_verified, :boolean
    field :confirmed_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @typedoc """
  Options for configuring whatsapp authentication.
  """
  @type whatsapp_options :: [
          expires_in: non_neg_integer()
        ]

  @doc """
  Generates a WhatsApp verification code and prepares the connection.

  This function creates a new WhatsApp verification code and its associated
  user NOTP (Number-based One-Time Password) record. It stores the polling token
  in the session and assigns the generated code to the connection.

  ## Options

     * `:expires_in` - Time in seconds until the code expires

  ## Returns

    A modified `conn` with:
     * The polling token stored in the session
     * The generated verification code assigned to conn.assigns.code

  """
  @spec generate_code(Conn.t(), whatsapp_options()) :: Conn.t()
  def generate_code(conn, opts \\ []) do
    {code, user_token} = generate_whatsapp_code(opts)

    conn
    |> put_session(:polling_token, user_token.sent_to)
    |> assign(:code, code)
  end

  defp generate_whatsapp_code(opts) do
    {code, user_token} = UserToken.build_code("whatsapp", opts)
    Repo.insert!(user_token)
    {code, user_token}
  end

  @doc """
  Whatsapp verify payload.

  ## Fields

    * `:code` - Verification code (required)
    * `:phone_number` - User phone number (required)

  ## Options

    * `:auto_signup` - Should we create a user if not exists (optional)
    * `:validate_phone_number` - Validates the uniqueness of the phone_number, in case
      you don't want to validate the uniqueness of the phone_number (like when
      using this changeset for validations on a LiveView form before
      submitting the form), this option can be set to `false`.
      Defaults to `true`.

  """
  @type whatsapp_verify_params :: %{
          required(:code) => String.t(),
          required(:phone_number) => String.t(),
          optional(:name) => String.t()
        }

  @type whatsapp_verify_options :: [
          auto_signup: boolean(),
          validate_phone_number: boolean()
        ]

  @spec verify(whatsapp_verify_params(), whatsapp_verify_options()) :: boolean()
  def verify(params, opts \\ []) do
    types = %{code: :string, phone_number: :string, name: :string}

    with {:ok, params} <- validate_params(params, types, [:code, :phone_number]),
         {:ok, token} <- verify_whatsapp_code(params["code"]),
         {:ok, user} <- find_or_maybe_create_user(params, opts) do
      change(token, user_id: user.id) |> AuthKit.Repo.update!()
      {:ok, user}
    else
      {:error, error} ->
        {:error, error}
    end
  end

  defp verify_whatsapp_code(code, _opts \\ []) do
    with {:ok, query} <- UserToken.verify_code_query(code, "whatsapp") do
      case Repo.one(query) do
        %UserToken{} = token ->
          {:ok, token |> change(confirmed_at: DateTime.utc_now()) |> Repo.update!()}

        nil ->
          {:error, :code_not_found}
      end
    else
      _ -> {:error, :invalid_code}
    end
  end

  defp find_or_maybe_create_user(params, opts) do
    cond do
      user = Repo.get_by(Whatsapp, phone_number: params["phone_number"]) ->
        {:ok, user}

      not Keyword.get(opts, :auto_signup, false) ->
        {:error, :user_not_found}

      Keyword.get(opts, :auto_signup) ->
        {:ok,
         create_user(
           %{
             phone_number: String.downcase(params["phone_number"]),
             phone_number_verified: true,
             name: params["name"]
           },
           opts
         )}
    end
  end

  defp create_user(params, opts) do
    %Whatsapp{}
    |> cast(params, [:name, :phone_number, :phone_number_verified])
    |> validate_required([:phone_number])
    |> validate_length(:phone_number, max: 60)
    |> maybe_validate_unique_phone_number(opts)
    |> Repo.insert!()
  end

  defp maybe_validate_unique_phone_number(changeset, opts) do
    if Keyword.get(opts, :validate_phone_number, true) do
      changeset
      |> unsafe_validate_unique(:phone_number, AuthKit.Repo)
      |> unique_constraint(:phone_number)
    else
      changeset
    end
  end

  @doc """
  Processes a WhatsApp verification check and handles user session creation.

  This function verifies the WhatsApp confirmation status using a polling token
  from the session and returns a tagged tuple indicating the result along with
  an appropriately modified connection.


  ## Returns
  * `{:ok, conn}` - When verification is successful, with conn set up for authentication
   and redirected to the appropriate page
  * `{:error, conn}` - When verification token is invalid or not found
  * `{:pending, conn}` - When verification is still pending completion
  """
  def check(conn, _opts \\ []) do
    polling_token = conn |> get_session(:polling_token)

    case check_whatsapp_confirmation(polling_token) do
      {:ok, user, _} ->
        token = Auth.generate_session_token(user)

        {:ok,
         conn
         |> renew_session()
         |> put_token_in_session(token)
         |> maybe_write_remember_me_cookie(token, conn.params)}

      {:error, :not_found} ->
        {:error, conn}

      {:error, :not_confirmed} ->
        {:pending, conn}
    end
  end

  defp check_whatsapp_confirmation(polling_token) do
    {:ok, query} = UserToken.check_confirmation(polling_token, "whatsapp")

    case Repo.one(query) do
      {_user, %UserToken{confirmed_at: nil}} ->
        {:error, :not_confirmed}

      {%Whatsapp{confirmed_at: nil} = user, %UserToken{confirmed_at: _confirmed_at}} ->
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        user
        |> change(confirmed_at: now)
        |> Auth.update_user_and_delete_all_tokens()

      {nil, %UserToken{confirmed_at: _confirmed_at}} ->
        {:error, :not_found}

      {user, token} ->
        Repo.delete!(token)
        {:ok, user, []}

      nil ->
        {:error, :not_found}
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
