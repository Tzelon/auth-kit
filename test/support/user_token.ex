defmodule AuthKit.Test.UserToken do
  @moduledoc false

  use AuthKit.Test.Schema
  use AuthKit.UserToken

  schema "users_tokens" do
    auth_kit_user_token_fields()
    auth_kit_active_tenant_field()
  end
end
