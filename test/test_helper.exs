database =
  :auth_kit
  |> Application.fetch_env!(AuthKit.Test.Repo)
  |> Keyword.fetch!(:database)

File.mkdir_p!(Path.dirname(database))
File.rm(database)
File.rm(database <> "-wal")
File.rm(database <> "-shm")

{:ok, _} = Application.ensure_all_started(:ecto_sqlite3)
{:ok, _} = AuthKit.Test.Repo.start_link()

# Sandbox mode :auto lets this process migrate. Tests check out their own
# connections after we switch back to :manual.
Ecto.Adapters.SQL.Sandbox.mode(AuthKit.Test.Repo, :auto)
Ecto.Migrator.run(AuthKit.Test.Repo, "test/support/migrations", :up, all: true)
Ecto.Adapters.SQL.Sandbox.mode(AuthKit.Test.Repo, :manual)

ExUnit.start()
