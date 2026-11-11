defmodule AuthKit.OAuth.JWKS do
  @moduledoc """
  Caches a JWKS document.

  One fetch serves a cache miss, including concurrent callers for the same
  URL. `max-age` is capped at 24 hours. A response with no `max-age`, or
  max-age 0, is stale on the next read. An unknown `kid` is fetched again
  only after 60 seconds from the last successful fetch of that URL.
  """

  use GenServer

  alias AuthKit.OAuth.{Error, HTTP}

  @call_timeout 20_000
  @unknown_kid_cooldown_ms 60_000
  @max_age_cap_seconds 86_400

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def key(url, kid) when is_binary(url) and is_binary(kid) and kid != "" do
    GenServer.call(__MODULE__, {:key, url, kid}, @call_timeout)
  end

  def key(_url, _kid), do: {:error, Error.exception(message: "Invalid ID token")}

  @impl true
  def init(cache), do: {:ok, cache}

  @impl true
  def handle_call({:key, url, kid}, _from, cache) do
    now = System.monotonic_time(:millisecond)

    case cache do
      %{^url => %{keys: keys, expires_at: expires_at} = entry} when expires_at > now ->
        case Map.get(keys, kid) do
          nil ->
            if now - entry.fetched_at >= @unknown_kid_cooldown_ms do
              fetch_and_reply(url, kid, cache)
            else
              {:reply, unknown_key(), cache}
            end

          jwk ->
            {:reply, {:ok, jwk}, cache}
        end

      _ ->
        fetch_and_reply(url, kid, cache)
    end
  end

  defp fetch_and_reply(url, kid, cache) do
    case fetch(url) do
      {:ok, keys, max_age} ->
        now = System.monotonic_time(:millisecond)

        entry = %{
          keys: keys,
          expires_at: now + max_age * 1_000,
          fetched_at: now
        }

        {:reply, reply_for(keys, kid), Map.put(cache, url, entry)}

      {:error, error} ->
        {:reply, {:error, error}, cache}
    end
  end

  defp reply_for(keys, kid) do
    case Map.get(keys, kid) do
      nil -> unknown_key()
      jwk -> {:ok, jwk}
    end
  end

  defp unknown_key do
    {:error, Error.exception(message: "Unknown ID token signing key")}
  end

  defp fetch(url) do
    case HTTP.get_full(url) do
      {:ok, 200, headers, %{"keys" => keys}} when is_list(keys) ->
        {:ok, index_keys(keys), max_age(headers)}

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
        if signing_key?(jwk), do: Map.put(acc, kid, jwk), else: acc

      _jwk, acc ->
        acc
    end)
  end

  defp signing_key?(jwk) do
    jwk["alg"] in [nil, "RS256"] and jwk["use"] in [nil, "sig"]
  end

  defp max_age(headers) do
    parsed =
      case headers["cache-control"] && Regex.run(~r/max-age=(\d+)/, headers["cache-control"]) do
        [_, seconds] -> String.to_integer(seconds)
        _ -> 0
      end

    min(parsed, @max_age_cap_seconds)
  end
end
