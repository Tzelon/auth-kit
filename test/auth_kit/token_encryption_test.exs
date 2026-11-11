defmodule AuthKit.TokenEncryptionTest do
  use AuthKit.DataCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity
  alias AuthKit.TokenEncryption

  test "round-trips a token and prefixes the ciphertext with the current version" do
    first = TokenEncryption.encrypt("gho_secret", :access_token)
    second = TokenEncryption.encrypt("gho_secret", :access_token)

    assert String.starts_with?(first, "ak1:")
    assert first != "gho_secret"
    assert first != second
    assert TokenEncryption.decrypt(first, :access_token) == "gho_secret"

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      TokenEncryption.decrypt(first, :refresh_token)
    end

    assert_raise ArgumentError, ~r/legacy plaintext/, fn ->
      TokenEncryption.decrypt("plain-legacy-token", :access_token)
    end
  end

  test "raises when ciphertext is tampered or the key does not match" do
    stored = TokenEncryption.encrypt("gho_secret", :access_token)
    ["ak1", rest] = String.split(stored, ":", parts: 2)
    {:ok, packed} = Base.decode64(rest, padding: false)
    flipped = "ak1:" <> Base.encode64(flip_last(packed), padding: false)

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      TokenEncryption.decrypt(flipped, :access_token)
    end

    keys = Application.fetch_env!(:auth_kit, :token_encryption_keys)
    other = :crypto.strong_rand_bytes(32) |> Base.encode64()
    replace_keys(%{1 => other})

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      TokenEncryption.decrypt(stored, :access_token)
    end

    replace_keys(%{1 => keys[1] <> "\n"})
    assert TokenEncryption.decrypt(stored, :access_token) == "gho_secret"
  end

  test "encrypts with the highest key version and still decrypts older prefixes" do
    keys = Application.fetch_env!(:auth_kit, :token_encryption_keys)
    older = TokenEncryption.encrypt("old-token", :access_token)
    assert String.starts_with?(older, "ak1:")

    replace_keys(Map.put(keys, 2, Base.encode64(:crypto.strong_rand_bytes(32))))
    newer = TokenEncryption.encrypt("new-token", :refresh_token)
    assert String.starts_with?(newer, "ak2:")
    assert TokenEncryption.decrypt(newer, :refresh_token) == "new-token"
    assert TokenEncryption.decrypt(older, :access_token) == "old-token"

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      TokenEncryption.decrypt(older, :id_token)
    end

    replace_keys(%{2 => keys[1]})

    assert_raise ArgumentError, ~r/unknown token encryption version ak1/, fn ->
      TokenEncryption.decrypt(older, :access_token)
    end
  end

  test "refuses to boot or encrypt without a versioned 32-byte key" do
    previous = Application.fetch_env!(:auth_kit, :token_encryption_keys)
    on_exit(fn -> Application.put_env(:auth_kit, :token_encryption_keys, previous) end)

    Application.delete_env(:auth_kit, :token_encryption_keys)

    assert_raise ArgumentError, ~r/token_encryption_keys is required/, fn ->
      TokenEncryption.ensure_configured!()
    end

    assert_raise ArgumentError, ~r/token_encryption_keys is required/, fn ->
      TokenEncryption.encrypt("gho_secret", :access_token)
    end

    Application.put_env(:auth_kit, :token_encryption_keys, %{1 => Base.encode64("too-short")})

    assert_raise ArgumentError, ~r/32 bytes/, fn ->
      TokenEncryption.ensure_configured!()
    end

    Application.put_env(:auth_kit, :token_encryption_keys, %{1 => "not base64!!!"})

    assert_raise ArgumentError, ~r/32 bytes/, fn ->
      TokenEncryption.encrypt("gho_secret", :access_token)
    end

    Application.put_env(:auth_kit, :token_encryption_keys, %{"1" => previous[1]})

    assert_raise ArgumentError, ~r/positive integers/, fn ->
      TokenEncryption.ensure_configured!()
    end

    Application.put_env(:auth_kit, :token_encryption_keys, %{0 => previous[1]})

    assert_raise ArgumentError, ~r/positive integers/, fn ->
      TokenEncryption.encrypt("gho_secret", :access_token)
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

  test "a ciphertext swapped between columns does not decrypt" do
    user = Fixtures.user_fixture()

    assert {:ok, _} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "swap-1", email: user.email, email_verified: true, name: "Ada"},
               %{
                 access_token: "access-secret",
                 refresh_token: "refresh-secret",
                 id_token: "id-secret"
               },
               auto_signup: false
             )

    [access_token, refresh_token, _id_token] = raw_tokens("swap-1")

    Repo.query!(
      "UPDATE identities SET access_token = ?, refresh_token = ? WHERE identity = ?",
      [refresh_token, access_token, "swap-1"]
    )

    assert_raise ArgumentError, ~r/could not decrypt/, fn ->
      Repo.get_by!(Identity, identity: "swap-1")
    end
  end

  test "refuses an unprefixed token unless legacy plaintext is allowed" do
    user = Fixtures.user_fixture()
    insert_oauth(user, "legacy-refuse")

    Repo.query!(
      "UPDATE identities SET access_token = ?, refresh_token = ?, id_token = ? WHERE identity = ?",
      ["plain-access", "plain-refresh", "plain-id", "legacy-refuse"]
    )

    assert_raise ArgumentError, ~r/legacy plaintext/, fn ->
      Repo.get_by!(Identity, identity: "legacy-refuse")
    end

    allow_legacy!()
    identity = Repo.get_by!(Identity, provider: "github", identity: "legacy-refuse")
    assert identity.access_token == "plain-access"
    assert identity.refresh_token == "plain-refresh"
    assert identity.id_token == "plain-id"
  end

  test "force_change re-encrypts an unchanged legacy token" do
    user = Fixtures.user_fixture()
    insert_oauth(user, "legacy-force")

    Repo.query!(
      "UPDATE identities SET access_token = ?, refresh_token = ?, id_token = ? WHERE identity = ?",
      ["plain-access", "plain-refresh", "plain-id", "legacy-force"]
    )

    allow_legacy!()
    identity = Repo.get_by!(Identity, provider: "github", identity: "legacy-force")

    identity
    |> Ecto.Changeset.change()
    |> Repo.update!()

    assert raw_tokens("legacy-force") == ["plain-access", "plain-refresh", "plain-id"]

    identity
    |> Ecto.Changeset.change()
    |> Ecto.Changeset.force_change(:access_token, identity.access_token)
    |> Repo.update!()

    identity = Repo.get_by!(Identity, provider: "github", identity: "legacy-force")
    assert identity.access_token == "plain-access"
    assert identity.refresh_token == "plain-refresh"

    [access_token, refresh_token, id_token] = raw_tokens("legacy-force")
    assert String.starts_with?(access_token, "ak1:")
    assert TokenEncryption.decrypt(access_token, :access_token) == "plain-access"
    assert refresh_token == "plain-refresh"
    assert id_token == "plain-id"
  end

  test "does not insert a plaintext token when the key is missing" do
    previous = Application.fetch_env!(:auth_kit, :token_encryption_keys)
    Application.delete_env(:auth_kit, :token_encryption_keys)
    on_exit(fn -> Application.put_env(:auth_kit, :token_encryption_keys, previous) end)

    user = Fixtures.user_fixture()

    assert_raise ArgumentError, ~r/token_encryption_keys/, fn ->
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

  defp insert_oauth(user, subject) do
    assert {:ok, _user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: subject, email: user.email, email_verified: true, name: "Ada"},
               %{access_token: "gho_first", refresh_token: "ghr_first", id_token: "id.one"},
               auto_signup: false
             )
  end

  defp allow_legacy! do
    previous = Application.get_env(:auth_kit, :allow_legacy_plaintext_tokens)
    Application.put_env(:auth_kit, :allow_legacy_plaintext_tokens, true)

    on_exit(fn ->
      if previous == nil do
        Application.delete_env(:auth_kit, :allow_legacy_plaintext_tokens)
      else
        Application.put_env(:auth_kit, :allow_legacy_plaintext_tokens, previous)
      end
    end)
  end

  defp replace_keys(keys) do
    previous = Application.get_env(:auth_kit, :token_encryption_keys)
    Application.put_env(:auth_kit, :token_encryption_keys, keys)

    on_exit(fn ->
      if previous == nil do
        Application.delete_env(:auth_kit, :token_encryption_keys)
      else
        Application.put_env(:auth_kit, :token_encryption_keys, previous)
      end
    end)
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
