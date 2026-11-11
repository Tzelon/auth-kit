defmodule AuthKit.OAuth.HTTP do
  @moduledoc false

  alias AuthKit.OAuth.Error

  @doc """
  Posts a form-encoded body and decodes the JSON response.
  """
  def post_form(url, body) do
    request = {
      String.to_charlist(url),
      [{~c"accept", ~c"application/json"}],
      ~c"application/x-www-form-urlencoded",
      URI.encode_query(body)
    }

    case dispatch(:post, request, url) do
      {:ok, status, _headers, decoded} -> {:ok, status, decoded}
      {:error, error} -> {:error, error}
    end
  end

  def get(url, headers) when is_list(headers) do
    case get_full(url, headers) do
      {:ok, status, _headers, decoded} -> {:ok, status, decoded}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  GETs `url` and returns the status, response headers, and decoded body.
  """
  def get_full(url, headers \\ []) when is_list(headers) do
    header_list =
      for {name, value} <- headers do
        {String.to_charlist(name), String.to_charlist(to_string(value))}
      end

    request = {
      String.to_charlist(url),
      [{~c"accept", ~c"application/json"} | header_list]
    }

    dispatch(:get, request, url)
  end

  defp dispatch(method, request, url) do
    case :httpc.request(method, request, http_options(), body_format: :binary) do
      {:ok, {{_version, status, _reason}, headers, response}} ->
        decoded =
          case JSON.decode(response) do
            {:ok, decoded} -> decoded
            {:error, _} -> response
          end

        {:ok, status, response_headers(headers), decoded}

      {:error, reason} ->
        {:error, Error.exception(message: "HTTP request to #{url} failed: #{inspect(reason)}")}
    end
  end

  defp response_headers(headers) do
    Map.new(headers, fn {key, value} ->
      {key |> to_string() |> String.downcase(), to_string(value)}
    end)
  end

  # :httpc does not verify server certificates unless told to.
  defp http_options do
    [
      timeout: 15_000,
      connect_timeout: 5_000,
      ssl: [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        depth: 3,
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ]
      ]
    ]
  end
end
