defmodule AuthKit.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    AuthKit.TokenEncryption.ensure_configured!()

    children = [AuthKit.OAuth.JWKS]

    Supervisor.start_link(children, strategy: :one_for_one, name: AuthKit.Supervisor)
  end
end
