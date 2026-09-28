defmodule AuthKit.Models.Identity do
  use AuthKit.Schema, prefix: "ident_"

  alias AuthKit.Models.User

  @derive {Inspect, except: [:access_token, :refresh_token, :id_token, :password, :provider_meta]}
  schema "identities" do
    field(:identity, :string)
    field(:provider, :string)
    field(:access_token, :string)
    field(:refresh_token, :string)
    field(:access_token_expires_at, :utc_datetime_usec)
    field(:refresh_token_expires_at, :utc_datetime_usec)
    field(:scope, :string)
    field(:id_token, :string)
    field(:clear_password, :string, virtual: true, redact: true)
    field(:password, :string)
    field(:state, Ecto.Enum, values: [:active, :reauth], default: :active)
    field(:provider_meta, :map, default: %{})

    belongs_to(:user, User)

    timestamps()
  end
end
