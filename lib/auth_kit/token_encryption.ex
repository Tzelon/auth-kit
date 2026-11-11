defmodule AuthKit.TokenEncryption do
  @moduledoc """
  AES-256-GCM for OAuth tokens stored on identities.

  The prefix is the key version (`ak1:` is version 1). Encryption uses the
  highest version in `:token_encryption_keys`. The additional authenticated
  data is that prefix plus the column name, so a ciphertext copied to a
  different token column does not decrypt.

  An unprefixed value loads only when `:allow_legacy_plaintext_tokens` is
  true. The next write of that field stores ciphertext for the current version.
  """

  @iv_bytes 12
  @tag_bytes 16
  @prefix ~r/^ak([1-9]\d*):(.*)/s
  @keys_cache :auth_kit_token_encryption_keys

  @doc """
  Raises unless `:token_encryption_keys` maps positive integer versions to 32-byte base64 keys.
  """
  def ensure_configured! do
    _ = keys!()
    :ok
  end

  def encrypt(plaintext, field) when is_binary(plaintext) and is_atom(field) do
    keys = keys!()
    version = keys |> Map.keys() |> Enum.max()
    seal(plaintext, version, Map.fetch!(keys, version), field)
  end

  def decrypt(ciphertext, field) when is_binary(ciphertext) and is_atom(field) do
    case parse(ciphertext) do
      {:ok, version, encoded} -> open(encoded, version, field)
      :unprefixed -> legacy(ciphertext)
    end
  end

  defp seal(plaintext, version, key, field) do
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        iv,
        plaintext,
        aad(version, field),
        @tag_bytes,
        true
      )

    "ak#{version}:" <> Base.encode64(iv <> tag <> ciphertext, padding: false)
  end

  defp open(encoded, version, field) do
    key =
      case Map.fetch(keys!(), version) do
        {:ok, key} -> key
        :error -> raise ArgumentError, "unknown token encryption version ak#{version}"
      end

    with {:ok, packed} <- Base.decode64(encoded, padding: false),
         <<iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes), ciphertext::binary>> <-
           packed,
         plain when is_binary(plain) <-
           :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             key,
             iv,
             ciphertext,
             aad(version, field),
             tag,
             false
           ) do
      plain
    else
      _ -> raise ArgumentError, "could not decrypt OAuth token"
    end
  end

  defp parse(ciphertext) do
    case Regex.run(@prefix, ciphertext) do
      [_, version, encoded] -> {:ok, String.to_integer(version), encoded}
      _ -> :unprefixed
    end
  end

  defp legacy(value) do
    if Application.get_env(:auth_kit, :allow_legacy_plaintext_tokens, false) == true do
      value
    else
      raise ArgumentError, "refusing legacy plaintext OAuth token"
    end
  end

  defp aad(version, field), do: "ak#{version}:#{field}"

  defp keys! do
    case Application.get_env(:auth_kit, :token_encryption_keys) do
      map when is_map(map) and map != %{} ->
        case :persistent_term.get(@keys_cache, :miss) do
          {^map, keys} ->
            keys

          _ ->
            keys = decode_keys!(map)
            :persistent_term.put(@keys_cache, {map, keys})
            keys
        end

      _ ->
        raise ArgumentError, key_error("is required")
    end
  end

  defp decode_keys!(map) do
    Map.new(map, fn {version, encoded} ->
      {version!(version), decode_key!(encoded)}
    end)
  end

  defp version!(version) when is_integer(version) and version > 0, do: version

  defp version!(_version) do
    raise ArgumentError, key_error("versions must be positive integers")
  end

  # A trailing newline from the environment is ignored.
  defp decode_key!(encoded) when is_binary(encoded) do
    case Base.decode64(String.trim(encoded)) do
      {:ok, key} when byte_size(key) == 32 -> key
      _ -> raise ArgumentError, key_error("values must be 32 bytes encoded as standard base64")
    end
  end

  defp decode_key!(_encoded) do
    raise ArgumentError, key_error("values must be 32 bytes encoded as standard base64")
  end

  defp key_error(detail) do
    """
    config :auth_kit, :token_encryption_keys #{detail}.
    Map each positive integer version to a key. Encryption uses the highest version.
    ak1 is version 1. OAuth tokens are not stored as plaintext.
    Generate a key with: openssl rand -base64 32
    """
  end
end
