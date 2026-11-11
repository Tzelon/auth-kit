defmodule AuthKit.OAuth.IDToken do
  @moduledoc false

  alias AuthKit.OAuth.{Error, JWKS}

  @issuers ["https://accounts.google.com", "accounts.google.com"]

  def verify(jwt, jwks_url, audience, nonce) when is_binary(jwt) and is_binary(jwks_url) do
    with {:ok, header, signing_input, signature, claims} <- decode(jwt),
         :ok <- check_alg(header),
         {:ok, kid} <- fetch_kid(header),
         {:ok, jwk} <- JWKS.key(jwks_url, kid),
         :ok <- verify_signature(signing_input, signature, jwk),
         :ok <- check_claims(claims, audience, nonce) do
      {:ok, claims}
    end
  end

  def verify(_jwt, _jwks_url, _audience, _nonce) do
    {:error, Error.exception(message: "Invalid ID token")}
  end

  defp decode(jwt) do
    case String.split(jwt, ".", parts: 3) do
      [header_segment, payload_segment, signature] ->
        with {:ok, header} <- decode_json(header_segment),
             {:ok, claims} <- decode_json(payload_segment) do
          {:ok, header, header_segment <> "." <> payload_segment, signature, claims}
        else
          _ -> {:error, Error.exception(message: "Invalid ID token")}
        end

      _ ->
        {:error, Error.exception(message: "Invalid ID token")}
    end
  end

  defp decode_json(segment) do
    with {:ok, json} <- Base.url_decode64(segment, padding: false),
         {:ok, value} when is_map(value) <- JSON.decode(json) do
      {:ok, value}
    else
      _ -> :error
    end
  end

  defp check_alg(%{"alg" => "RS256"}), do: :ok
  defp check_alg(_header), do: {:error, Error.exception(message: "Invalid ID token")}

  defp fetch_kid(%{"kid" => kid}) when is_binary(kid) and kid != "", do: {:ok, kid}
  defp fetch_kid(_header), do: {:error, Error.exception(message: "Invalid ID token")}

  defp verify_signature(signing_input, signature, jwk) do
    with {:ok, signature} <- Base.url_decode64(signature, padding: false),
         {:ok, public_key} <- rsa_public_key(jwk),
         true <- rsa_verify(signing_input, signature, public_key) do
      :ok
    else
      _ -> {:error, Error.exception(message: "Invalid ID token signature")}
    end
  end

  defp rsa_verify(signing_input, signature, public_key) do
    :public_key.verify(signing_input, :sha256, signature, public_key)
  rescue
    _ -> false
  end

  defp rsa_public_key(%{"n" => n, "e" => e}) do
    with {:ok, n} <- Base.url_decode64(n, padding: false),
         {:ok, e} <- Base.url_decode64(e, padding: false) do
      {:ok, {:RSAPublicKey, :binary.decode_unsigned(n), :binary.decode_unsigned(e)}}
    else
      _ -> :error
    end
  end

  defp rsa_public_key(_jwk), do: :error

  defp check_claims(claims, audience, nonce) do
    with :ok <- check_claim(claims["iss"] in @issuers, "Invalid issuer"),
         :ok <- check_claim(claims["aud"] == audience, "Invalid audience"),
         :ok <- check_claim(not expired?(claims["exp"]), "ID token has expired"),
         :ok <- check_azp(claims["azp"], audience),
         :ok <- check_claim(claims["nonce"] == nonce, "Invalid nonce"),
         # Callers match accounts by email, so an unverified email must never get through.
         :ok <- check_claim(claims["email_verified"] in [true, "true"], "Email is not verified") do
      :ok
    end
  end

  defp expired?(exp) when is_integer(exp), do: exp <= System.system_time(:second)
  defp expired?(_exp), do: true

  defp check_azp(nil, _client_id), do: :ok

  defp check_azp(azp, client_id) when is_binary(azp) and azp == client_id, do: :ok

  defp check_azp(_azp, _client_id) do
    {:error, Error.exception(message: "Invalid authorized party")}
  end

  defp check_claim(true, _message), do: :ok
  defp check_claim(false, message), do: {:error, Error.exception(message: message)}
end
