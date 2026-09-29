defmodule AuthKit.Test.TenantMember do
  @moduledoc false

  use AuthKit.Test.Schema
  use AuthKit.TenantMember

  schema "tenant_members" do
    auth_kit_tenant_member_fields()
    timestamps(type: :utc_datetime)
  end
end
