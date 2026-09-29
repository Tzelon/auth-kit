import Config

config :logger, level: :warning

# ecto_sqlite3 defaults to Jason. Elixir's built-in JSON module is enough here.
config :ecto_sqlite3, json_library: JSON

# SQLite database used only by this library's tests. Host apps bring their own repo.
config :auth_kit,
  ecto_repos: [AuthKit.Test.Repo],
  repo: AuthKit.Test.Repo

config :auth_kit, AuthKit.Test.Repo,
  database: Path.expand("../tmp/auth_kit_test.db", __DIR__),
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10
