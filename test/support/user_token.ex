defmodule AuthKit.Test.UserToken do
  @moduledoc false

  use AuthKit.Schema, prefix: "usrtkn_"
  use AuthKit.UserToken

  schema "users_tokens" do
    auth_kit_user_token_fields()
  end
end
