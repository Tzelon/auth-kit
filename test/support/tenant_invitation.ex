defmodule AuthKit.Test.TenantInvitation do
  @moduledoc false

  use AuthKit.Test.Schema
  use AuthKit.TenantInvitation

  schema "tenant_invitations" do
    auth_kit_tenant_invitation_fields()
    timestamps(type: :utc_datetime)
  end
end
