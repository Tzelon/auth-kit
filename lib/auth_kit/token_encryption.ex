defmodule AuthKit.TokenEncryption do
  @moduledoc """
  AES-256-GCM for OAuth tokens stored on identities.

  Ciphertext starts with `ak1:`, the key version. A value without that
  prefix is legacy plaintext. The next write of that field stores `ak1:`
  ciphertext.
  """

  @version "ak1:"
  @iv_bytes 12
  @tag_bytes 16

  @doc """
  Raises when `:token_encryption_key` is missing or not 32 bytes of standard base64.
  """
  def ensure_configured! do
    _ = key!()
    :ok
  end

  def encrypt(plaintext) when is_binary(plaintext) do
    key = key!()
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, @version, @tag_bytes, true)

    @version <> Base.encode64(iv <> tag <> ciphertext, padding: false)
  end

  def decrypt(@version <> encoded) do
    with {:ok, packed} <- Base.decode64(encoded, padding: false),
         <<iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes), ciphertext::binary>> <-
           packed,
         plain when is_binary(plain) <-
           :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             key!(),
             iv,
             ciphertext,
             @version,
             tag,
             false
           ) do
      plain
    else
      _ -> raise ArgumentError, "could not decrypt OAuth token"
    end
  end

  def decrypt(plaintext) when is_binary(plaintext), do: plaintext

  # A trailing newline from the environment is ignored.
  defp key! do
    case Application.get_env(:auth_kit, :token_encryption_key) do
      encoded when is_binary(encoded) ->
        case Base.decode64(String.trim(encoded)) do
          {:ok, key} when byte_size(key) == 32 ->
            key

          _ ->
            raise ArgumentError, key_error("must be 32 bytes encoded as standard base64")
        end

      _ ->
        raise ArgumentError, key_error("is required")
    end
  end

  defp key_error(detail) do
    """
    config :auth_kit, :token_encryption_key #{detail}.
    OAuth tokens are not stored as plaintext.
    Generate one with: openssl rand -base64 32
    """
  end
end
