defmodule AuthKit.OAuth.JWKS do
  @moduledoc """
  Caches a JWKS document.

  One fetch serves a cache miss, including concurrent callers for the same
  URL, and does not block a hit for a different URL. `max-age` is capped at
  24 hours. A response with no `max-age`, or max-age 0, is stale on the next
  read. An unknown `kid` is fetched again only after 60 seconds from `fetched_at`.
  A failed fetch is reused for 8 seconds when no fresh document is cached.
  A failed refetch keeps that document and moves `fetched_at` forward.
  A lookup that times out returns an error.
  """

  use GenServer

  alias AuthKit.OAuth.{Error, HTTP}

  @task_supervisor __MODULE__.TaskSupervisor
  @call_timeout 30_000
  @fetch_timeout_ms 8_000
  @failure_ttl_ms 8_000
  @unknown_kid_cooldown_ms 60_000
  @max_age_cap_seconds 86_400

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def key(url, kid) when is_binary(url) and is_binary(kid) and kid != "" do
    try do
      GenServer.call(__MODULE__, {:key, url, kid}, @call_timeout)
    catch
      :exit, _reason ->
        {:error, Error.exception(message: "JWKS request failed")}
    end
  end

  def key(_url, _kid), do: {:error, Error.exception(message: "Invalid ID token")}

  @impl true
  def init(_cache), do: {:ok, %{entries: %{}, inflight: %{}}}

  @impl true
  def handle_call({:key, url, kid}, from, state) do
    now = System.monotonic_time(:millisecond)

    case fresh(state.entries[url], now) do
      %{status: :ok, keys: keys} = entry ->
        case Map.get(keys, kid) do
          nil ->
            if now - entry.fetched_at >= @unknown_kid_cooldown_ms do
              await_fetch(url, kid, from, state)
            else
              {:reply, unknown_key(), state}
            end

          jwk ->
            {:reply, {:ok, jwk}, state}
        end

      %{status: :error, error: error} ->
        {:reply, {:error, error}, state}

      _ ->
        await_fetch(url, kid, from, state)
    end
  end

  @impl true
  def handle_info({ref, result}, state) when is_reference(ref) do
    finish_fetch(ref, result, state)
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    error = Error.exception(message: "JWKS request failed: #{inspect(reason)}")
    finish_fetch(ref, {:error, error}, state)
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp fresh(%{expires_at: expires_at} = entry, now) when expires_at > now, do: entry
  defp fresh(_entry, _now), do: nil

  defp await_fetch(url, kid, from, state) do
    case state.inflight do
      %{^url => flight} ->
        flight = %{flight | waiters: [{from, kid} | flight.waiters]}
        {:noreply, %{state | inflight: Map.put(state.inflight, url, flight)}}

      _ ->
        start_fetch(url, kid, from, state)
    end
  end

  defp start_fetch(url, kid, from, state) do
    %Task{ref: ref} =
      Task.Supervisor.async_nolink(@task_supervisor, fn -> fetch(url) end)

    flight = %{ref: ref, waiters: [{from, kid}]}
    {:noreply, %{state | inflight: Map.put(state.inflight, url, flight)}}
  end

  defp finish_fetch(ref, result, state) do
    case Enum.find(state.inflight, fn {_url, flight} -> flight.ref == ref end) do
      {url, %{waiters: waiters}} ->
        Process.demonitor(ref, [:flush])
        now = System.monotonic_time(:millisecond)
        entry = remember(result, state.entries[url], now)

        for {from, kid} <- Enum.reverse(waiters) do
          GenServer.reply(from, reply_waiter(result, entry, kid))
        end

        {:noreply,
         %{
           state
           | inflight: Map.delete(state.inflight, url),
             entries: Map.put(state.entries, url, entry)
         }}

      nil ->
        {:noreply, state}
    end
  end

  defp remember({:error, error}, previous, now) do
    case fresh(previous, now) do
      %{status: :ok} = existing -> %{existing | fetched_at: now}
      _ -> entry_from({:error, error}, now)
    end
  end

  defp remember(result, _previous, now), do: entry_from(result, now)

  defp entry_from({:ok, keys, max_age}, now) do
    %{
      status: :ok,
      keys: keys,
      expires_at: now + max_age * 1_000,
      fetched_at: now
    }
  end

  defp entry_from({:error, error}, now) do
    %{status: :error, error: error, expires_at: now + @failure_ttl_ms}
  end

  defp reply_waiter({:error, error}, %{status: :ok, keys: keys}, kid) do
    case Map.get(keys, kid) do
      nil -> {:error, error}
      jwk -> {:ok, jwk}
    end
  end

  defp reply_waiter(_result, entry, kid), do: reply_for(entry, kid)

  defp reply_for(%{status: :error, error: error}, _kid), do: {:error, error}

  defp reply_for(%{status: :ok, keys: keys}, kid) do
    case Map.get(keys, kid) do
      nil -> unknown_key()
      jwk -> {:ok, jwk}
    end
  end

  defp unknown_key do
    {:error, Error.exception(message: "Unknown ID token signing key")}
  end

  defp fetch(url) do
    case HTTP.get_full(url, [], timeout: @fetch_timeout_ms, connect_timeout: 3_000) do
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
