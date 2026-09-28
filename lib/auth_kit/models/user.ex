defmodule AuthKit.Models.User do
  use AuthKit.Schema, prefix: "usr_"

  alias AuthKit.Models.Identity

  @type t :: %__MODULE__{}

  schema "users" do
    field(:email, :string)
    field(:name, :string)
    field(:phone_number, :string)
    field(:phone_number_verified, :boolean)
    field(:avatar_url, :string)
    field(:confirmed_at, :utc_datetime)

    has_many(:identities, Identity)

    timestamps(type: :utc_datetime)
  end
end
