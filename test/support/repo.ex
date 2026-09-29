defmodule AuthKit.Test.Repo do
  @moduledoc false

  use Ecto.Repo,
    otp_app: :auth_kit,
    adapter: Ecto.Adapters.SQLite3
end
