defmodule AuthKit.Test.User do
  @moduledoc """
  User schema for AuthKit's own tests and development. Host apps
  configure their own with `config :auth_kit, user: MyApp.User`.
  """

  use AuthKit.Test.Schema
  use AuthKit.UserSchema

  schema "users" do
    field :email, :string
    field :name, :string
    field :phone_number, :string
    field :phone_verified_at, :utc_datetime
    field :avatar_url, :string
    field :email_confirmed_at, :utc_datetime

    has_many :identities, AuthKit.Test.Identity

    timestamps(type: :utc_datetime)
  end
end
