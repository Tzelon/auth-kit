defmodule AuthKit.DataCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  using do
    quote do
      alias AuthKit.Test.Repo

      import Ecto
      import Ecto.Query
      import AuthKit.DataCase
    end
  end

  setup tags do
    AuthKit.DataCase.setup_sandbox(tags)
    :ok
  end

  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(AuthKit.Test.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end
end
