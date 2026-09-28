defmodule AuthKit.Schema do
  @moduledoc """
  Shared schema setup: prefixed KSUID primary keys, such as `usr_2EXLuF3dU8v4L4JLInQXNWpjKE0`.
  """

  defmacro __using__(opts \\ []) do
    primary_key_opts = Keyword.merge(opts, autogenerate: true, dump_prefix: true)

    quote do
      use Ecto.Schema

      @primary_key {:id, EctoKsuid, unquote(primary_key_opts)}
      @foreign_key_type :string
    end
  end
end
