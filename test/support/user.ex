defmodule AuthKit.Test.User do
  @moduledoc """
  User schema for AuthKit's own tests and development. Host apps
  configure their own with `config :auth_kit, user: MyApp.User`.
  """

  use AuthKit.Schema, prefix: "usr_"

  schema "users" do
    field :email, :string
    field :name, :string
    field :phone_number, :string
    field :phone_number_verified, :boolean
    field :avatar_url, :string
    field :email_confirmed_at, :utc_datetime

    has_many :identities, AuthKit.Models.Identity

    timestamps(type: :utc_datetime)
  end
end
