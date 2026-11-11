defmodule AuthKit.Email do
  @moduledoc false

  def normalize(email) when is_binary(email), do: email |> String.trim() |> String.downcase()
  def normalize(other), do: other
end
