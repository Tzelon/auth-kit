defmodule AuthKit.Test.Identity do
  @moduledoc false

  use AuthKit.Schema, prefix: "ident_"
  use AuthKit.Identity

  schema "identities" do
    auth_kit_identity_fields()
    timestamps()
  end
end
