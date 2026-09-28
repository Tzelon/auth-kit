defmodule AuthKit.Repo do
  @moduledoc """
  Forwards calls to the host app's Ecto repo, set with:

      config :auth_kit, repo: MyApp.Repo
  """

  def repo, do: Application.fetch_env!(:auth_kit, :repo)

  def one(queryable, opts \\ []), do: repo().one(queryable, opts)
  def get_by(queryable, clauses, opts \\ []), do: repo().get_by(queryable, clauses, opts)
  def preload(structs, preloads, opts \\ []), do: repo().preload(structs, preloads, opts)
  def insert!(struct, opts \\ []), do: repo().insert!(struct, opts)
  def update(changeset, opts \\ []), do: repo().update(changeset, opts)
  def update!(changeset, opts \\ []), do: repo().update!(changeset, opts)
  def delete!(struct, opts \\ []), do: repo().delete!(struct, opts)
  def delete_all(queryable, opts \\ []), do: repo().delete_all(queryable, opts)
  def transaction(multi, opts \\ []), do: repo().transaction(multi, opts)
end
