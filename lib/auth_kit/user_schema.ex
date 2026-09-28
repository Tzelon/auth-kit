defmodule AuthKit.UserSchema do
  @moduledoc """
  Checks, when your user schema compiles, that it has what AuthKit needs.

      defmodule MyApp.User do
        use Ecto.Schema
        use AuthKit.UserSchema

        schema "users" do
          # ...
        end
      end
  """

  @fields [:email, :name, :avatar_url, :phone_number, :phone_verified_at, :email_confirmed_at]
  @associations [:identities]

  defmacro __using__(_opts) do
    quote do
      @after_verify AuthKit.UserSchema
    end
  end

  def __after_verify__(module) do
    missing =
      (@fields -- module.__schema__(:fields)) ++
        (@associations -- module.__schema__(:associations))

    if missing != [] do
      raise CompileError,
        description: "#{inspect(module)} is missing what AuthKit needs: #{inspect(missing)}"
    end

    :ok
  end
end
