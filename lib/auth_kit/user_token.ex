defmodule AuthKit.UserToken do
  @moduledoc """
  Fields for your user token schema, and the token queries AuthKit runs on it.

      defmodule MyApp.UserToken do
        use Ecto.Schema
        use AuthKit.UserToken

        schema "users_tokens" do
          auth_kit_user_token_fields()
        end
      end

  Then set `config :auth_kit, user_token: MyApp.UserToken`.
  """

  import Ecto.Query

  @hash_algorithm :sha256
  @rand_size 32

  @code_regex ~r/\b([A-Z0-9]{4}(?:-[A-Z0-9]{4}){3})\b/

  # Define a small buffer (e.g., 30 seconds) to account for time drift when checking expires_at
  @buffer_seconds 30

  # It is very important to keep the magic link token expiry short,
  # since someone with access to the email may take over the account.
  @magic_link_validity_in_minutes 15
  @confirm_validity_in_minutes 7 * 24 * 60
  @reset_password_validity_in_minutes 24 * 60
  @code_validity_in_minutes 10
  @session_validity_in_days 60

  defmacro __using__(_opts) do
    quote do
      import AuthKit.UserToken, only: [auth_kit_user_token_fields: 0]
    end
  end

  @doc """
  Defines the user token fields, the `:user` association and timestamps.
  """
  defmacro auth_kit_user_token_fields do
    quote do
      field :token, :binary
      field :context, :string
      field :sent_to, :string
      field :confirmed_at, :utc_datetime_usec
      field :expires_at, :utc_datetime_usec

      belongs_to :user, AuthKit.Config.user_schema()

      timestamps(type: :utc_datetime, updated_at: false)
    end
  end

  @doc """
  Generates a token that will be stored in a signed place,
  such as session or cookie. As they are signed, those
  tokens do not need to be hashed.

  Session tokens are stored in the database so individual sessions
  can be expired.
  """
  def build_session_token(user, opts \\ []) do
    token = :crypto.strong_rand_bytes(@rand_size)

    expires_at =
      DateTime.add(
        DateTime.utc_now(),
        Keyword.get(opts, :expires_in, @session_validity_in_days),
        :day
      )

    {token,
     struct(schema(),
       token: token,
       context: "session",
       user_id: user.id,
       expires_at: expires_at
     )}
  end

  @doc """
  Checks if the token is valid and returns its underlying lookup query.

  The query returns the user found by the token, if any.

  The token is valid if it matches the value in the database and it has
  not expired (after @session_validity_in_days).
  """
  def verify_session_token_query(token) do
    query =
      from token in by_token_and_context_query(token, "session"),
        join: user in assoc(token, :user),
        where: token.expires_at > ^DateTime.utc_now(),
        select: user

    {:ok, query}
  end

  @doc """
  Builds a token and its hash to be delivered to the user's email.

  The non-hashed token is sent to the user email while the
  hashed part is stored in the database. The original token cannot be reconstructed,
  which means anyone with read-only access to the database cannot directly use
  the token in the application to gain access. Furthermore, if the user changes
  their email in the system, the tokens sent to the previous email are no longer
  valid.
  """
  def build_email_token(user, context, opts \\ []) do
    build_hashed_token(user, context, user.email, opts)
  end

  defp build_hashed_token(user, context, sent_to, opts) do
    token = :crypto.strong_rand_bytes(@rand_size)
    hashed_token = :crypto.hash(@hash_algorithm, token)

    expires_at =
      DateTime.add(
        DateTime.utc_now(),
        Keyword.get(opts, :expires_in, minutes_for_context(context)),
        :minute
      )

    {Base.url_encode64(token, padding: false),
     struct(schema(),
       token: hashed_token,
       expires_at: expires_at,
       context: context,
       sent_to: sent_to,
       user_id: user.id
     )}
  end

  def build_code(context, opts \\ []) do
    sent_to =
      :crypto.strong_rand_bytes(@rand_size)
      |> Base.url_encode64(padding: false)

    build_hashed_code(context, sent_to, opts)
  end

  defp build_hashed_code(context, sent_to, opts) do
    charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Generate all random bytes at once
    code =
      :crypto.strong_rand_bytes(16)
      |> :binary.bin_to_list()
      |> Enum.map(&String.at(charset, rem(&1, String.length(charset))))
      |> Enum.chunk_every(4)
      |> Enum.map(&Enum.join/1)
      |> Enum.join("-")

    hashed_code = :crypto.hash(@hash_algorithm, code)

    expires_at =
      DateTime.add(
        DateTime.utc_now(),
        Keyword.get(opts, :expires_in, minutes_for_context(context)),
        :minute
      )

    {code,
     struct(schema(),
       token: hashed_code,
       expires_at: expires_at,
       context: context,
       sent_to: sent_to
     )}
  end

  @doc """
  Checks if the token is valid and returns its underlying lookup query.

  If found, the query returns a tuple of the form `{user, token}`.

  The given token is valid if it matches its hashed counterpart in the
  database and it is being used within the window for `"login"`.
  """
  def verify_magic_link_token_query(token) do
    verify_email_token_query(token, "login")
  end

  @doc """
  Checks an email token for any context and returns its lookup query.

  If found, the query returns a tuple of the form `{user, token}`.

  The token is valid when it matches its hashed counterpart, its `sent_to`
  is still the user's email, and it is inside the window from
  `minutes_for_context/1` (`"login"`, `"confirm"`, or `"reset_password"`).
  """
  def verify_email_token_query(token, context) when is_binary(token) and is_binary(context) do
    case Base.url_decode64(token, padding: false) do
      {:ok, decoded_token} ->
        hashed_token = :crypto.hash(@hash_algorithm, decoded_token)
        minutes = minutes_for_context(context)

        query =
          from token in by_token_and_context_query(hashed_token, context),
            join: user in assoc(token, :user),
            where: token.inserted_at > ago(^minutes, "minute"),
            where: token.sent_to == user.email,
            select: {user, token}

        {:ok, query}

      :error ->
        :error
    end
  end

  @doc """
  Checks if the code is valid and returns its underlying lookup query.

  The query returns the token found by the code, if any.
  """
  def verify_code_query(code, context) do
    case Regex.run(@code_regex, code) do
      [_, code] ->
        hashed_token = :crypto.hash(@hash_algorithm, code)

        query =
          from token in by_token_and_context_query(hashed_token, context),
            where:
              token.expires_at > datetime_add(^DateTime.utc_now(), -@buffer_seconds, "second"),
            select: token

        {:ok, query}

      nil ->
        :error
    end
  end

  @doc """
  Checks if the token confirmed and returns its underlying lookup query

  The query returns the user found by the token, if any.

  This is used to validate session confirmed by other devices.
  """
  def check_confirmation(sent_to, context) do
    query =
      from token in schema(),
        where: [sent_to: ^sent_to, context: ^context],
        left_join: user in assoc(token, :user),
        select: {user, token}

    {:ok, query}
  end

  defp minutes_for_context("login"), do: @magic_link_validity_in_minutes
  defp minutes_for_context("confirm"), do: @confirm_validity_in_minutes
  defp minutes_for_context("reset_password"), do: @reset_password_validity_in_minutes
  defp minutes_for_context("whatsapp"), do: @code_validity_in_minutes

  @doc """
  Returns the token struct for the given token value and context.
  """
  def by_token_and_context_query(token, context) do
    from schema(), where: [token: ^token, context: ^context]
  end

  @doc """
  Gets all tokens for the given user for the given contexts.
  """
  def by_user_and_contexts_query(user, :all) do
    from t in schema(), where: t.user_id == ^user.id
  end

  def by_user_and_contexts_query(user, [_ | _] = contexts) do
    from t in schema(), where: t.user_id == ^user.id and t.context in ^contexts
  end

  @doc """
  Deletes a list of tokens.
  """
  def delete_all_query(tokens) do
    from t in schema(), where: t.id in ^Enum.map(tokens, & &1.id)
  end

  defp schema, do: AuthKit.Config.user_token_schema()
end
