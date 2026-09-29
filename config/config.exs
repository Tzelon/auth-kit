import Config

# Only used when working on AuthKit itself. A dependency's config is
# never loaded by the host app, which sets its own :user.
config :auth_kit,
  user: AuthKit.Test.User,
  identity: AuthKit.Test.Identity,
  user_token: AuthKit.Test.UserToken,
  tenant: AuthKit.Test.Tenant,
  tenant_member: AuthKit.Test.TenantMember,
  tenant_invitation: AuthKit.Test.TenantInvitation

if config_env() == :test do
  import_config "test.exs"
end
