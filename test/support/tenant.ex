defmodule AuthKit.Test.Tenant do
  @moduledoc false

  use AuthKit.Test.Schema
  use AuthKit.Tenant

  schema "tenants" do
    auth_kit_tenant_fields()
    timestamps(type: :utc_datetime)
  end
end
