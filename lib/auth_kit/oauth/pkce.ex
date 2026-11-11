defmodule AuthKit.OAuth.PKCE do
  @moduledoc false

  alias AuthKit.OAuth.Error

  @default_ttl_seconds 600

  def generate do
    verifier = random_token()
    challenge = :crypto.hash(:sha256, verifier) |> Base.url_encode64(padding: false)

    %{
      code_verifier: verifier,
      code_challenge: challenge,
      code_challenge_method: "S256"
    }
  end

  def check(params, session_params) when is_map(session_params) do
    with :ok <- check_state(params, session_params),
         :ok <- check_ttl(session_params) do
      fetch_verifier(session_params)
    end
  end

  def check(_params, _session_params) do
    {:error, Error.exception(message: "Invalid state param, possible CSRF attempt")}
  end

  defp check_state(params, session_params) do
    expected = session_params[:state] || session_params["state"]
    actual = params["state"]

    if is_binary(expected) and is_binary(actual) and byte_size(expected) == byte_size(actual) and
         :crypto.hash_equals(expected, actual) do
      :ok
    else
      {:error, Error.exception(message: "Invalid state param, possible CSRF attempt")}
    end
  end

  defp check_ttl(session_params) do
    issued_at = session_params[:issued_at] || session_params["issued_at"]
    now = System.system_time(:second)

    if is_integer(issued_at) and issued_at <= now and now - issued_at < ttl_seconds() do
      :ok
    else
      {:error, Error.exception(message: "OAuth state has expired")}
    end
  end

  defp fetch_verifier(session_params) do
    case session_params[:code_verifier] || session_params["code_verifier"] do
      verifier when is_binary(verifier) and verifier != "" ->
        {:ok, verifier}

      _ ->
        {:error, Error.exception(message: "Missing code verifier")}
    end
  end

  defp ttl_seconds do
    case Application.get_env(:auth_kit, :oauth_state_ttl, @default_ttl_seconds) do
      seconds when is_integer(seconds) and seconds > 0 ->
        seconds

      other ->
        raise ArgumentError,
              "config :auth_kit, :oauth_state_ttl must be a positive integer number of seconds, got: #{inspect(other)}"
    end
  end

  defp random_token do
    32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end
end
