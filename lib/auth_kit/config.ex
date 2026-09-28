defmodule AuthKit.Config do
  @moduledoc """
  Compile-time configuration.

      config :auth_kit, user: MyApp.User, identity: MyApp.Identity, user_token: MyApp.UserToken

  AuthKit reads these values when it compiles, so after changing them
  run `mix deps.compile auth_kit --force`.
  """

  @user Application.compile_env(:auth_kit, :user) ||
          raise(ArgumentError, """
          AuthKit needs your user schema. Add this to config/config.exs:

              config :auth_kit, user: MyApp.User, identity: MyApp.Identity, user_token: MyApp.UserToken
          """)

  @identity Application.compile_env(:auth_kit, :identity) ||
              raise(ArgumentError, """
              AuthKit needs your identity schema. Add this to config/config.exs:

                  config :auth_kit, identity: MyApp.Identity
              """)

  @user_token Application.compile_env(:auth_kit, :user_token) ||
                raise(ArgumentError, """
                AuthKit needs your user token schema. Add this to config/config.exs:

                    config :auth_kit, user_token: MyApp.UserToken
                """)

  @doc """
  The Ecto schema for users, set with `config :auth_kit, user: MyApp.User`.
  """
  def user_schema, do: @user

  @doc """
  The Ecto schema for identities, set with `config :auth_kit, identity: MyApp.Identity`.
  """
  def identity_schema, do: @identity

  @doc """
  The Ecto schema for user tokens, set with `config :auth_kit, user_token: MyApp.UserToken`.
  """
  def user_token_schema, do: @user_token
end
