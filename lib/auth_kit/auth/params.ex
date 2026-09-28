defmodule AuthKit.Auth.Params do
  @moduledoc """
  Validates request params with schemaless Ecto changesets.
  """

  import Ecto.Changeset

  @email_format ~r/^[^\s]+@[^\s]+$/
  @email_max_length 160
  @password_min_length 8
  @password_max_length 128

  @doc """
  Casts `params` to `types`, checks `required` fields and runs the optional
  `validations` function on the changeset.

  Returns every field in `types` with string keys, `nil` when not given, or
  a map of error messages per field.
  """
  def validate(params, types, required \\ [], validations \\ &Function.identity/1) do
    {%{}, types}
    |> cast(params, Map.keys(types))
    |> validate_required(required)
    |> validations.()
    |> apply_action(:validate)
    |> case do
      {:ok, data} ->
        {:ok, Map.new(Map.keys(types), &{Atom.to_string(&1), Map.get(data, &1)})}

      {:error, changeset} ->
        {:error, errors_to_map(changeset)}
    end
  end

  @doc """
  Checks the email format and length.
  """
  def validate_email_format(changeset) do
    changeset
    |> validate_format(:email, @email_format, message: "must have the @ sign and no spaces")
    |> validate_length(:email, max: @email_max_length)
  end

  @doc """
  Checks the password length.
  """
  def validate_password_length(changeset) do
    validate_length(changeset, :password, min: @password_min_length, max: @password_max_length)
  end

  defp errors_to_map(changeset) do
    changeset
    |> traverse_errors(fn {message, opts} ->
      Regex.replace(~r/%{(\w+)}/, message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Map.new(fn {field, messages} -> {Atom.to_string(field), messages} end)
  end
end
