defmodule AuthKit.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    AuthKit.TokenEncryption.ensure_configured!()

    children = [
      {Task.Supervisor, name: AuthKit.OAuth.JWKS.TaskSupervisor},
      AuthKit.OAuth.JWKS
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: AuthKit.Supervisor)
  end
end
