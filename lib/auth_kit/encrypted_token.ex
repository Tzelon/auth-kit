defmodule AuthKit.EncryptedToken do
  @moduledoc false

  use Ecto.Type

  def type, do: :string

  def cast(nil), do: {:ok, nil}
  def cast(value) when is_binary(value), do: {:ok, value}
  def cast(_), do: :error

  def dump(nil), do: {:ok, nil}
  def dump(value) when is_binary(value), do: {:ok, AuthKit.TokenEncryption.encrypt(value)}
  def dump(_), do: :error

  def load(nil), do: {:ok, nil}
  def load(value) when is_binary(value), do: {:ok, AuthKit.TokenEncryption.decrypt(value)}
  def load(_), do: :error
end
