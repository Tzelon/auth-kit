defmodule AuthKit.Config do
  @moduledoc """
  Compile-time configuration.

      config :auth_kit, user: MyApp.User

  AuthKit reads these values when it compiles, so after changing them
  run `mix deps.compile auth_kit --force`.
  """

  @user Application.compile_env(:auth_kit, :user) ||
          raise(ArgumentError, """
          AuthKit needs your user schema. Add this to config/config.exs:

              config :auth_kit, user: MyApp.User
          """)

  @doc """
  The Ecto schema for users, set with `config :auth_kit, user: MyApp.User`.
  """
  def user_schema, do: @user
end
