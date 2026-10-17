defmodule AuthKit.Test.IntegerUserToken do
  @moduledoc false

  use Ecto.Schema
  use AuthKit.UserToken

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "integer_users_tokens" do
    auth_kit_user_token_fields()
    auth_kit_api_key_fields()
  end
end
