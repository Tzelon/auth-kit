defmodule AuthKit.TokenEncryptionTest do
  use AuthKit.DataCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity
  alias AuthKit.TokenEncryption

  test "round-trips a token and prefixes the ciphertext" do
    first = TokenEncryption.encrypt("gho_secret")
    second = TokenEncryption.encrypt("gho_secret")

    assert String.starts_with?(first, "ak1:")
    assert first != "gho_secret"
    assert first != second
    assert TokenEncryption.decrypt(first) == "gho_secret"
    assert TokenEncryption.decrypt("plain-legacy-token") == "plain-legacy-token"
  end

  test "raises when ciphertext is tampered or the key does not match" do
    stored = TokenEncryption.encrypt("gho_secret")
    <<prefix::binary-size(4), rest::binary>> = stored
    flipped = prefix <> flip_last(rest)

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      TokenEncryption.decrypt(flipped)
    end

    previous = Application.fetch_env!(:auth_kit, :token_encryption_key)
    other = :crypto.strong_rand_bytes(32) |> Base.encode64()
    Application.put_env(:auth_kit, :token_encryption_key, other)

    on_exit(fn -> Application.put_env(:auth_kit, :token_encryption_key, previous) end)

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      TokenEncryption.decrypt(stored)
    end
  end

  test "refuses to boot or encrypt without a 32-byte key" do
    previous = Application.fetch_env!(:auth_kit, :token_encryption_key)

    on_exit(fn -> Application.put_env(:auth_kit, :token_encryption_key, previous) end)

    Application.delete_env(:auth_kit, :token_encryption_key)

    assert_raise ArgumentError, ~r/token_encryption_key is required/, fn ->
      TokenEncryption.ensure_configured!()
    end

    assert_raise ArgumentError, ~r/token_encryption_key is required/, fn ->
      TokenEncryption.encrypt("gho_secret")
    end

    Application.put_env(:auth_kit, :token_encryption_key, Base.encode64("too-short"))

    assert_raise ArgumentError, ~r/32 bytes/, fn ->
      TokenEncryption.ensure_configured!()
    end

    Application.put_env(:auth_kit, :token_encryption_key, "not base64!!!")

    assert_raise ArgumentError, ~r/32 bytes/, fn ->
      TokenEncryption.encrypt("gho_secret")
    end
  end

  test "stores ciphertext and still returns plaintext on the identity" do
    user = Fixtures.user_fixture()

    assert {:ok, _user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "enc-1", email: user.email, email_verified: true, name: "Ada"},
               %{
                 access_token: "gho_new",
                 refresh_token: "ghr_new",
                 id_token: "header.payload.sig"
               },
               auto_signup: false
             )

    identity = Repo.get_by!(Identity, provider: "github", identity: "enc-1")
    assert identity.access_token == "gho_new"
    assert identity.refresh_token == "ghr_new"
    assert identity.id_token == "header.payload.sig"

    [access_token, refresh_token, id_token] = raw_tokens("enc-1")
    assert String.starts_with?(access_token, "ak1:")
    assert String.starts_with?(refresh_token, "ak1:")
    assert String.starts_with?(id_token, "ak1:")
    refute access_token == "gho_new"
  end

  test "loads legacy plaintext and encrypts it the next time that field is written" do
    user = Fixtures.user_fixture()

    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "legacy-1", email: user.email, email_verified: true, name: "Ada"},
               %{access_token: "gho_first", refresh_token: "ghr_first", id_token: "id.one"},
               auto_signup: false
             )

    Repo.query!(
      "UPDATE identities SET access_token = ?, refresh_token = ?, id_token = ? WHERE identity = ?",
      ["plain-access", "plain-refresh", "plain-id", "legacy-1"]
    )

    identity = Repo.get_by!(Identity, provider: "github", identity: "legacy-1")
    assert identity.access_token == "plain-access"
    assert identity.refresh_token == "plain-refresh"
    assert identity.id_token == "plain-id"

    assert {:ok, _} =
             Auth.update_user_tokens(user, %{provider: "github", access_token: "gho_next"})

    identity = Repo.get_by!(Identity, provider: "github", identity: "legacy-1")
    assert identity.access_token == "gho_next"
    assert identity.refresh_token == "plain-refresh"
    assert identity.id_token == "plain-id"

    [access_token, refresh_token, id_token] = raw_tokens("legacy-1")
    assert String.starts_with?(access_token, "ak1:")
    assert refresh_token == "plain-refresh"
    assert id_token == "plain-id"
  end

  test "does not insert a plaintext token when the key is missing" do
    previous = Application.fetch_env!(:auth_kit, :token_encryption_key)
    Application.delete_env(:auth_kit, :token_encryption_key)
    on_exit(fn -> Application.put_env(:auth_kit, :token_encryption_key, previous) end)

    user = Fixtures.user_fixture()

    assert_raise ArgumentError, ~r/token_encryption_key/, fn ->
      Auth.link_identity(%{
        user_id: user.id,
        provider: "github",
        identity: "missing-key",
        access_token: "gho_should_not_land"
      })
    end

    refute Repo.get_by(Identity, identity: "missing-key")

    %{rows: rows} =
      Repo.query!("SELECT access_token FROM identities WHERE access_token = ?", [
        "gho_should_not_land"
      ])

    assert rows == []
  end

  defp raw_tokens(subject) do
    %{rows: [[access_token, refresh_token, id_token]]} =
      Repo.query!(
        "SELECT access_token, refresh_token, id_token FROM identities WHERE identity = ?",
        [subject]
      )

    [access_token, refresh_token, id_token]
  end

  defp flip_last(encoded) do
    size = byte_size(encoded)
    last = :binary.last(encoded)
    binary_part(encoded, 0, size - 1) <> <<Bitwise.bxor(last, 1)>>
  end
end
