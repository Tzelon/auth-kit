defmodule AuthKit.Config do
  @moduledoc """
  Compile-time configuration.

      config :auth_kit, user: MyApp.User

  AuthKit reads these values when it compiles, so after changing them
  run `mix deps.compile auth_kit --force`.
  """

  @user Application.compile_env(:auth_kit, :user, AuthKit.Models.User)

  @doc """
  The Ecto schema for users. Defaults to `AuthKit.Models.User`.
  """
  def user_schema, do: @user
end
