defmodule AuthKit.Auth do
  import Ecto.Query
  import Ecto.Changeset

  alias AuthKit.Models.{Identity, UserToken}
  alias AuthKit.Repo

  @user AuthKit.Config.user_schema()

  def fetch_user_by_email(email, opts \\ []) do
    user = Repo.one(from u in AuthKit.Config.user_schema(), where: u.email == ^email)

    if preload = Keyword.get(opts, :preload) do
      user |> Repo.preload(preload)
    else
      user
    end
  end

  @doc """
  Gets the user with the given signed token.
  """
  def fetch_user_by_session_token(token) do
    {:ok, query} = UserToken.verify_session_token_query(token)
    Repo.one(query)
  end

  @doc """
  Create a user.

  It is important to validate the length of email.
  Otherwise databases may truncate the email without warnings, which
  could lead to unpredictable or insecure behaviour. 

  ## Options

    * `:validate_email` - Validates the uniqueness of the email, in case
      you don't want to validate the uniqueness of the email (like when
      using this changeset for validations on a LiveView form before
      submitting the form), this option can be set to `false`.
      Defaults to `true`.
  """
  def create_user(attrs, opts \\ []) do
    struct(@user)
    |> cast(attrs, [:email, :name, :avatar_url, :phone_number, :phone_verified_at])
    |> validate_required([:email, :name])
    |> validate_email(opts)
    |> Repo.insert!()
  end

  @doc """
  Link user to identity.

  It is important to validate the length of the password.
  Long passwords may be very expensive to hash for certain algorithms.

  ## Options

    * `:hash_password` - Hashes the password so it can be stored securely
      in the database and ensures the password field is cleared to prevent
      leaks in the logs. If password hashing is not needed and clearing the
      password field is not desired (like when using this changeset for
      validations on a LiveView form), this option can be set to `false`.
      Defaults to `true`.

  """
  def link_identity(attrs, opts \\ []) do
    %Identity{}
    |> cast(attrs, [
      :user_id,
      :provider,
      :identity,
      :password,
      :access_token,
      :refresh_token,
      :access_token_expires_at,
      :refresh_token_expires_at,
      :scope,
      :id_token,
      :state,
      :provider_meta
    ])
    |> validate_required([:user_id, :provider, :identity])
    |> validate_password(opts)
    |> Repo.insert!()
  end

  @doc """
  Updates a user tokens or create a new identity for the user.

  ## Examples

      iex> update_tokens(attrs)
      {:ok, %User{}}

      iex> update_tokens(attrs, [])
      {:error, %Ecto.Changeset{}}

  """
  def update_user_tokens(user, attrs, _opts \\ []) when is_struct(user, @user) do
    if identity = get_user_identity_by_provider(user, attrs.provider) do
      {:ok, _identity} = update_identity_tokens(identity, attrs)
      {:ok, Repo.preload(user, :identities, force: true)}
    else
      _ = link_identity(Map.put(attrs, :user_id, user.id))
      {:ok, Repo.preload(user, :identities, force: true)}
    end
  end

  defp update_identity_tokens(%Identity{} = identity, attrs) do
    # We do not want to update fields to nil
    attrs = Enum.reject(attrs, fn {_, v} -> is_nil(v) end) |> Map.new()

    identity
    |> cast(attrs, [
      :access_token,
      :refresh_token,
      :access_token_expires_at,
      :refresh_token_expires_at,
      :scope,
      :id_token,
      :state,
      :provider_meta
    ])
    |> Repo.update()
  end

  @spec get_user_identity_by_provider(struct(), binary()) :: struct() | nil
  def get_user_identity_by_provider(%{id: id} = user, provider) when is_struct(user, @user) do
    Repo.one(
      from idn in Identity,
        where:
          idn.user_id == ^id and
            idn.provider == ^to_string(provider)
    )
  end

  def generate_session_token(user) when is_struct(user, @user) do
    {token, user_token} = UserToken.build_session_token(user)
    Repo.insert!(user_token)
    token
  end

  @doc """
  Deletes the signed token with the given context.
  """
  def delete_session_token(token) do
    Repo.delete_all(UserToken.by_token_and_context_query(token, "session"))
    :ok
  end

  def generate_login_token(user) when is_struct(user, @user) do
    {encoded_token, user_token} = UserToken.build_email_token(user, "login")
    Repo.insert!(user_token)
    encoded_token
  end

  @doc """
  Logs the user in by magic link.

  There are two cases to consider:

  1. The user has already confirmed their email. They are logged in
     and the magic link is expired.

  2. The user has not confirmed their email. The user gets confirmed
     with `confirm_user_email/1`, which also removes any password set
     before the email was proven.
  """
  def verify_login_token(token) do
    with {:ok, query} <- UserToken.verify_magic_link_token_query(token) do
      case Repo.one(query) do
        {%{email_confirmed_at: nil} = user, _token} ->
          confirm_user_email(user)

        {user, token} ->
          Repo.delete!(token)
          {:ok, user, []}

        nil ->
          {:error, :not_found}
      end
    else
      _ -> {:error, :invalid_token}
    end
  end

  @doc """
  Confirms the user's email once they have proven they own it, through
  a magic link or a verified email from an OAuth provider.

  Password sign-up does not verify the email, so on an unconfirmed
  account the password may have been set by someone else. Confirming
  removes the password identity and expires all tokens, including
  sessions. Already confirmed users are returned unchanged.
  """
  def confirm_user_email(%{email_confirmed_at: nil} = user) when is_struct(user, @user) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    user
    |> change(email_confirmed_at: now)
    |> update_user_and_delete_all_tokens(delete_password: true)
  end

  def confirm_user_email(user) when is_struct(user, @user), do: {:ok, user, []}

  @doc """
  Gets the user linked to the given provider identity, such as a
  Google `sub`.
  """
  def fetch_user_by_identity(provider, identity) do
    Repo.one(
      from u in AuthKit.Config.user_schema(),
        join: idn in assoc(u, :identities),
        where: idn.provider == ^to_string(provider) and idn.identity == ^identity
    )
  end

  @doc """
  Verifies the password.

  If there is no user or the user doesn't have a password, we call
  `AuthKit.Password.no_user_verify/0` to avoid timing attacks.
  """
  def valid_password?(%Identity{password: hashed_password}, password)
      when byte_size(password) > 0 do
    AuthKit.Password.verify_pass(password, hashed_password)
  end

  def valid_password?(_, _) do
    AuthKit.Password.no_user_verify()
    {:error, :invalide_password}
  end

  defp validate_email(changeset, opts) do
    changeset
    |> validate_required([:email])
    |> AuthKit.Auth.Params.validate_email_format()
    |> maybe_validate_unique_email(opts)
  end

  defp maybe_validate_unique_email(changeset, opts) do
    if Keyword.get(opts, :validate_email, true) do
      changeset
      |> unsafe_validate_unique(:email, AuthKit.Repo.repo())
      |> unique_constraint(:email)
    else
      changeset
    end
  end

  defp validate_password(changeset, opts) do
    changeset
    |> AuthKit.Auth.Params.validate_password_length()
    # Examples of additional password validation:
    # |> validate_format(:password, ~r/[a-z]/, message: "at least one lower case character")
    # |> validate_format(:password, ~r/[A-Z]/, message: "at least one upper case character")
    # |> validate_format(:password, ~r/[!?@#$%^&*_0-9]/, message: "at least one digit or punctuation character")
    |> maybe_hash_password(opts)
  end

  defp maybe_hash_password(changeset, opts) do
    hash_password? = Keyword.get(opts, :hash_password, true)
    password = get_change(changeset, :password)

    if hash_password? && password && changeset.valid? do
      changeset
      # Hashing could be done with `Ecto.Changeset.prepare_changes/2`, but that
      # would keep the database transaction open longer and hurt performance.
      |> put_change(:password, AuthKit.Password.hash_pwd_salt(password))
    else
      changeset
    end
  end

  ## Token helper

  @doc """
  Updates the user and deletes all their tokens in one transaction.

  ## Options

    * `:delete_password` - Also deletes the user's password identity.
      Defaults to `false`.
  """
  def update_user_and_delete_all_tokens(changeset, opts \\ []) do
    %{data: user} = changeset

    with {:ok, %{user: user, tokens_to_expire: expired_tokens}} <-
           Ecto.Multi.new()
           |> Ecto.Multi.update(:user, changeset)
           |> Ecto.Multi.all(:tokens_to_expire, UserToken.by_user_and_contexts_query(user, :all))
           |> Ecto.Multi.delete_all(:tokens, fn %{tokens_to_expire: tokens_to_expire} ->
             UserToken.delete_all_query(tokens_to_expire)
           end)
           |> maybe_delete_password(user, opts)
           |> Repo.transaction() do
      {:ok, user, expired_tokens}
    end
  end

  defp maybe_delete_password(multi, user, opts) do
    if Keyword.get(opts, :delete_password, false) do
      Ecto.Multi.delete_all(
        multi,
        :password,
        from(idn in Identity, where: idn.user_id == ^user.id and idn.provider == "credential")
      )
    else
      multi
    end
  end
end
