defmodule AuthKit.TenantInvitation do
  @moduledoc """
  Fields for your tenant invitation schema.

      defmodule MyApp.TenantInvitation do
        use Ecto.Schema
        use AuthKit.TenantInvitation

        schema "tenant_invitations" do
          auth_kit_tenant_invitation_fields()
          timestamps()
        end
      end

  Then set `config :auth_kit, tenant_invitation: MyApp.TenantInvitation`.
  """

  defmacro __using__(_opts) do
    quote do
      import AuthKit.TenantInvitation, only: [auth_kit_tenant_invitation_fields: 0]
    end
  end

  @doc """
  Defines the invitation fields and the tenant and inviter associations.

  `token` stores the hash of the secret sent to `send_invitation`. The raw
  secret is not kept.
  """
  defmacro auth_kit_tenant_invitation_fields do
    quote do
      field :email, :string
      field :role, {:array, :string}

      field :status, Ecto.Enum,
        values: [:pending, :accepted, :rejected, :canceled],
        default: :pending

      field :token, :binary, redact: true
      field :expires_at, :utc_datetime_usec

      belongs_to :tenant, AuthKit.Config.tenant_schema()
      belongs_to :inviter, AuthKit.Config.user_schema(), foreign_key: :inviter_id
    end
  end
end
