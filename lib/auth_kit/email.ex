defmodule AuthKit.Email do
  @moduledoc false

  @doc """
  Trims and downcases an email address.
  """
  def normalize(email) when is_binary(email), do: email |> String.trim() |> String.downcase()
  def normalize(other), do: other
end
