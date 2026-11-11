defmodule AuthKit.EncryptedToken do
  @moduledoc false

  use Ecto.ParameterizedType

  def init(opts) do
    %{field: Keyword.fetch!(opts, :field)}
  end

  def type(_params), do: :string

  def cast(nil, _params), do: {:ok, nil}
  def cast(value, _params) when is_binary(value), do: {:ok, value}
  def cast(_value, _params), do: :error

  def dump(nil, _dumper, _params), do: {:ok, nil}

  def dump(value, _dumper, %{field: field}) when is_binary(value) do
    {:ok, AuthKit.TokenEncryption.encrypt(value, field)}
  end

  def dump(_value, _dumper, _params), do: :error

  def load(nil, _loader, _params), do: {:ok, nil}

  def load(value, _loader, %{field: field}) when is_binary(value) do
    {:ok, AuthKit.TokenEncryption.decrypt(value, field)}
  end

  def load(_value, _loader, _params), do: :error
end
