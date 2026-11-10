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

    request(:post, request, url)
  end

  @doc """
  Sends a GET and decodes a JSON response.

  `headers` is a list of `{name, value}` string pairs, added after `accept`.
  """
  def get(url, headers) when is_list(headers) do
    header_list =
      for {name, value} <- headers do
        {String.to_charlist(name), String.to_charlist(to_string(value))}
      end

    request = {
      String.to_charlist(url),
      [{~c"accept", ~c"application/json"} | header_list]
    }

    request(:get, request, url)
  end

  defp request(method, request, url) do
    case :httpc.request(method, request, http_options(), body_format: :binary) do
      {:ok, {{_version, status, _reason}, _headers, response}} ->
        case JSON.decode(response) do
          {:ok, decoded} -> {:ok, status, decoded}
          {:error, _} -> {:ok, status, response}
        end

      {:error, reason} ->
        {:error, Error.exception(message: "HTTP request to #{url} failed: #{inspect(reason)}")}
    end
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
