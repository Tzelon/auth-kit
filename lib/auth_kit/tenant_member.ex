defmodule AuthKit.TenantMember do
  @moduledoc """
  Fields for your tenant member schema.

      defmodule MyApp.TenantMember do
        use Ecto.Schema
        use AuthKit.TenantMember

        schema "tenant_members" do
          auth_kit_tenant_member_fields()
          timestamps()
        end
      end

  Then set `config :auth_kit, tenant_member: MyApp.TenantMember`.
  """

  defmacro __using__(_opts) do
    quote do
      import AuthKit.TenantMember, only: [auth_kit_tenant_member_fields: 0]
    end
  end

  @doc """
  Defines the membership fields and the tenant and user associations.
  """
  defmacro auth_kit_tenant_member_fields do
    quote do
      field :role, {:array, :string}, default: ["member"]

      belongs_to :tenant, AuthKit.Config.tenant_schema()
      belongs_to :user, AuthKit.Config.user_schema()
    end
  end
end
