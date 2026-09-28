defmodule AuthKit.Password do
  @moduledoc """
  Password hashing with PBKDF2-HMAC-SHA256, built on Erlang's `:crypto`.

  Hashes are stored as `$pbkdf2-sha256$<iterations>$<salt>$<hash>`, with the
  salt and hash base64 encoded. The iteration count is kept in each hash, so
  it can be raised later without invalidating existing passwords.
  """

  @prefix "pbkdf2-sha256"
  # OWASP recommendation for PBKDF2-HMAC-SHA256.
  @iterations 600_000
  @salt_bytes 16
  @hash_bytes 32

  @doc """
  Hashes the password with a random salt.
  """
  def hash_pwd_salt(password) when is_binary(password) do
    salt = :crypto.strong_rand_bytes(@salt_bytes)
    hash = pbkdf2(password, salt, @iterations, @hash_bytes)

    Enum.join(["", @prefix, @iterations, encode(salt), encode(hash)], "$")
  end

  @doc """
  Checks the password against a stored hash in constant time.
  """
  def verify_pass(password, stored_hash) when is_binary(password) and is_binary(stored_hash) do
    with ["", @prefix, iterations, salt, hash] <- String.split(stored_hash, "$"),
         {iterations, ""} when iterations > 0 <- Integer.parse(iterations),
         {:ok, salt} <- decode(salt),
         {:ok, hash} <- decode(hash) do
      password
      |> pbkdf2(salt, iterations, byte_size(hash))
      |> :crypto.hash_equals(hash)
    else
      _ -> no_user_verify()
    end
  end

  def verify_pass(_password, _stored_hash), do: no_user_verify()

  @doc """
  Runs a dummy hash so a check against a missing user takes as long as a
  check against a real one. Always returns `false`.
  """
  def no_user_verify do
    hash_pwd_salt("")
    false
  end

  defp pbkdf2(password, salt, iterations, length) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, length)
  end

  defp encode(bytes), do: Base.encode64(bytes, padding: false)

  defp decode(string), do: Base.decode64(string, padding: false)
end
