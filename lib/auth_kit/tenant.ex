defmodule AuthKit.Tenant do
  @moduledoc """
  Fields for your tenant schema.

      defmodule MyApp.Tenant do
        use Ecto.Schema
        use AuthKit.Tenant

        schema "tenants" do
          auth_kit_tenant_fields()
          timestamps()
        end
      end

  Then set `config :auth_kit, tenant: MyApp.Tenant`.
  """

  defmacro __using__(_opts) do
    quote do
      import AuthKit.Tenant, only: [auth_kit_tenant_fields: 0]
    end
  end

  @doc """
  Defines the tenant fields and the member and invitation associations.
  """
  defmacro auth_kit_tenant_fields do
    quote do
      field :name, :string
      field :slug, :string
      field :logo, :string
      field :metadata, :map, default: %{}

      has_many :members, AuthKit.Config.tenant_member_schema(), foreign_key: :tenant_id
      has_many :invitations, AuthKit.Config.tenant_invitation_schema(), foreign_key: :tenant_id
    end
  end
end
