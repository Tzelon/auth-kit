defmodule AuthKit.Identity do
  @moduledoc """
  Fields for your identity schema: one row per way a user signs in, such as
  a password or a Google account.

      defmodule MyApp.Identity do
        use Ecto.Schema
        use AuthKit.Identity

        schema "identities" do
          auth_kit_identity_fields()
          timestamps()
        end
      end

  Then set `config :auth_kit, identity: MyApp.Identity`.

  `access_token`, `refresh_token`, and `id_token` are plaintext on the
  struct. New writes store AES-256-GCM ciphertext prefixed with `ak1:`.
  A value without that prefix loads unchanged.
  """

  defmacro __using__(_opts) do
    quote do
      import AuthKit.Identity, only: [auth_kit_identity_fields: 0]
    end
  end

  @doc """
  Defines the identity fields and the `:user` association.
  """
  defmacro auth_kit_identity_fields do
    quote do
      field :identity, :string
      field :provider, :string
      field :access_token, AuthKit.EncryptedToken, redact: true
      field :refresh_token, AuthKit.EncryptedToken, redact: true
      field :access_token_expires_at, :utc_datetime_usec
      field :refresh_token_expires_at, :utc_datetime_usec
      field :scope, :string
      field :id_token, AuthKit.EncryptedToken, redact: true
      field :clear_password, :string, virtual: true, redact: true
      field :password, :string, redact: true
      field :state, Ecto.Enum, values: [:active, :reauth], default: :active
      field :provider_meta, :map, default: %{}, redact: true

      belongs_to :user, AuthKit.Config.user_schema()
    end
  end
end
