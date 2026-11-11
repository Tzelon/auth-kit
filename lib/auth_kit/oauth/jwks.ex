defmodule AuthKit.OAuth.JWKS do
  @moduledoc """
  Fetches a JWKS document and keeps it until `Cache-Control` max-age elapses.

  A fresh cache that does not contain the requested `kid` is fetched once more.
  A missing max-age, or max-age 0, is stale on the next read.
  """

  use GenServer

  alias AuthKit.OAuth.{Error, HTTP}

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def key(url, kid) when is_binary(url) and is_binary(kid) and kid != "" do
    try do
      case GenServer.call(__MODULE__, {:lookup, url, kid}) do
        {:ok, jwk} ->
          {:ok, jwk}

        :unknown ->
          refetch(url, kid)

        :miss ->
          case fetch_and_read(url, kid) do
            {:ok, jwk} -> {:ok, jwk}
            :missing -> refetch(url, kid)
            {:error, _} = error -> error
          end
      end
    catch
      :exit, _reason ->
        {:error, Error.exception(message: "JWKS request failed")}
    end
  end

  def key(_url, _kid), do: {:error, Error.exception(message: "Invalid ID token")}

  @impl true
  def init(cache), do: {:ok, cache}

  @impl true
  def handle_call({:lookup, url, kid}, _from, cache) do
    now = System.monotonic_time(:millisecond)

    reply =
      case cache do
        %{^url => {keys, expires_at}} when expires_at > now ->
          case Map.get(keys, kid) do
            nil -> :unknown
            jwk -> {:ok, jwk}
          end

        _ ->
          :miss
      end

    {:reply, reply, cache}
  end

  def handle_call({:read, url, kid}, _from, cache) do
    reply =
      case cache do
        %{^url => {keys, _expires_at}} ->
          case Map.get(keys, kid) do
            nil -> :missing
            jwk -> {:ok, jwk}
          end

        _ ->
          :missing
      end

    {:reply, reply, cache}
  end

  def handle_call({:store, url, keys, max_age}, _from, cache) do
    expires_at = System.monotonic_time(:millisecond) + max_age * 1_000
    {:reply, :ok, Map.put(cache, url, {keys, expires_at})}
  end

  defp refetch(url, kid) do
    with :ok <- fetch(url),
         {:ok, jwk} <- GenServer.call(__MODULE__, {:read, url, kid}) do
      {:ok, jwk}
    else
      :missing -> {:error, Error.exception(message: "Unknown ID token signing key")}
      {:error, %Error{}} = error -> error
    end
  end

  defp fetch_and_read(url, kid) do
    with :ok <- fetch(url) do
      GenServer.call(__MODULE__, {:read, url, kid})
    end
  end

  defp fetch(url) do
    case HTTP.get_full(url) do
      {:ok, 200, headers, %{"keys" => keys}} when is_list(keys) ->
        GenServer.call(__MODULE__, {:store, url, index_keys(keys), max_age(headers)})
        :ok

      {:ok, status, _headers, _body} ->
        {:error, Error.exception(message: "JWKS request failed with status #{status}")}

      {:error, error} ->
        {:error, error}
    end
  end

  defp index_keys(keys) do
    Enum.reduce(keys, %{}, fn
      %{"kty" => "RSA", "kid" => kid, "n" => n, "e" => e} = jwk, acc
      when is_binary(kid) and kid != "" and is_binary(n) and is_binary(e) ->
        if jwk["alg"] in [nil, "RS256"], do: Map.put(acc, kid, jwk), else: acc

      _jwk, acc ->
        acc
    end)
  end

  defp max_age(headers) do
    case headers["cache-control"] && Regex.run(~r/max-age=(\d+)/, headers["cache-control"]) do
      [_, seconds] -> String.to_integer(seconds)
      _ -> 0
    end
  end
end
