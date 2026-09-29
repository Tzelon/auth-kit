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

  @tenant Application.compile_env(:auth_kit, :tenant)
  @tenant_member Application.compile_env(:auth_kit, :tenant_member)
  @tenant_invitation Application.compile_env(:auth_kit, :tenant_invitation)

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

  @doc """
  The Ecto schema for tenants, set with `config :auth_kit, tenant: MyApp.Tenant`.

  Optional. `AuthKit.Tenants` raises if a tenant schema is missing.
  """
  def tenant_schema, do: schema!(@tenant, :tenant)

  @doc """
  The Ecto schema for tenant members, set with `config :auth_kit, tenant_member: MyApp.TenantMember`.
  """
  def tenant_member_schema, do: schema!(@tenant_member, :tenant_member)

  @doc """
  The Ecto schema for tenant invitations, set with `config :auth_kit, tenant_invitation: MyApp.TenantInvitation`.
  """
  def tenant_invitation_schema, do: schema!(@tenant_invitation, :tenant_invitation)

  defp schema!(module, _key) when is_atom(module) and not is_nil(module), do: module

  defp schema!(_, key) do
    raise ArgumentError, """
    AuthKit tenants need your #{key} schema. Add this to config/config.exs:

        config :auth_kit,
          tenant: MyApp.Tenant,
          tenant_member: MyApp.TenantMember,
          tenant_invitation: MyApp.TenantInvitation
    """
  end
end
