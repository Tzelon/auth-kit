defmodule AuthKit.ConnCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  using do
    quote do
      import Plug.Conn
      import Plug.Test
      import AuthKit.ConnCase

      alias AuthKit.Test.Repo
    end
  end

  setup tags do
    AuthKit.DataCase.setup_sandbox(tags)
    {:ok, conn: build_conn()}
  end

  def build_conn do
    :get
    |> Plug.Test.conn("/")
    |> Map.replace!(:secret_key_base, secret_key_base())
    |> Plug.Test.init_test_session(%{})
  end

  def secret_key_base, do: String.duplicate("a", 64)

  def redirected_to(conn, status \\ 302) do
    assert conn.status == status
    [location] = Plug.Conn.get_resp_header(conn, "location")
    location
  end
end
