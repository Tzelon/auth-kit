defmodule AuthKit.OAuthSignInTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.Auth2
  alias AuthKit.Auth.MagicLink
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity
  alias AuthKit.Test.User

  test "auto_signup true creates a confirmed user from a verified profile" do
    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "github",
               %{
                 identity: "100",
                 email: "ADA@example.com",
                 email_verified: true,
                 name: "Ada",
                 avatar_url: "https://example.com/ada.png"
               },
               %{access_token: "gho_new", scope: "read:user,user:email"},
               auto_signup: true
             )

    assert user.email == "ada@example.com"
    assert user.name == "Ada"
    assert user.avatar_url == "https://example.com/ada.png"
    assert user.email_confirmed_at

    identity = Repo.get_by!(Identity, provider: "github", identity: "100")
    assert identity.user_id == user.id
    assert identity.access_token == "gho_new"
    assert identity.scope == "read:user,user:email"
    assert Repo.aggregate(User, :count) == 1
  end

  test "auto_signup false links a verified email when the case differs" do
    {existing, password} = Fixtures.user_with_password_fixture(%{email: "ada@example.com"})
    credential = Repo.get_by!(Identity, user_id: existing.id, provider: "credential")
    assert Auth.valid_password?(credential, password)
    refute existing.email_confirmed_at

    assert {:ok, linked} =
             Auth.sign_in_with_oauth(
               "github",
               %{
                 identity: "101",
                 email: "Ada@Example.com",
                 email_verified: true,
                 name: "Ada Lovelace"
               },
               %{access_token: "gho_link"},
               auto_signup: false
             )

    assert linked.id == existing.id
    assert linked.email == "ada@example.com"
    assert linked.email_confirmed_at
    refute Repo.get_by(Identity, user_id: existing.id, provider: "credential")

    identity = Repo.get_by!(Identity, provider: "github", identity: "101")
    assert identity.user_id == existing.id
    assert identity.access_token == "gho_link"
    assert Repo.aggregate(User, :count) == 1
  end

  test "refuses an unverified email and writes nothing" do
    assert {:error, :email_not_verified} =
             Auth.sign_in_with_oauth(
               "google",
               %{
                 identity: "google-unverified",
                 email: "ada@example.com",
                 email_verified: false,
                 name: "Ada"
               },
               %{access_token: "ya29"}
             )

    assert Repo.aggregate(User, :count) == 0
    assert Repo.aggregate(Identity, :count) == 0
  end

  test "unverified profile does not link an existing user" do
    {existing, password} = Fixtures.user_with_password_fixture(%{email: "ada@example.com"})
    credential = Repo.get_by!(Identity, user_id: existing.id, provider: "credential")

    assert {:error, :email_not_verified} =
             Auth.sign_in_with_oauth(
               "github",
               %{
                 identity: "unverified",
                 email: "Ada@Example.com",
                 email_verified: false,
                 name: "Ada"
               },
               %{access_token: "gho_nope"}
             )

    user = Repo.get!(User, existing.id)
    refute user.email_confirmed_at
    assert Auth.valid_password?(Repo.get!(Identity, credential.id), password)
    refute Repo.get_by(Identity, provider: "github", identity: "unverified")
    assert Repo.aggregate(User, :count) == 1
    assert Repo.aggregate(Identity, :count) == 1
  end

  test "auto_signup false returns user_not_found and writes nothing" do
    assert {:error, :user_not_found} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "404", email: "ada@example.com", email_verified: true, name: "Ada"},
               %{}
             )

    assert Repo.aggregate(User, :count) == 0
    assert Repo.aggregate(Identity, :count) == 0
  end

  test "signing in an existing identity refreshes tokens" do
    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "55", email: "ada@example.com", email_verified: true, name: "Ada"},
               %{access_token: "gho_first", scope: "read:user"},
               auto_signup: true
             )

    assert {:ok, again} =
             Auth.sign_in_with_oauth(
               "github",
               %{
                 identity: "55",
                 email: "other@example.com",
                 email_verified: false,
                 name: "Someone Else"
               },
               %{access_token: "gho_second", scope: "read:user,user:email"},
               auto_signup: false
             )

    assert again.id == user.id
    assert again.email == "ada@example.com"
    assert Repo.aggregate(User, :count) == 1
    assert Repo.aggregate(Identity, :count) == 1

    identity = Repo.get_by!(Identity, provider: "github", identity: "55")
    assert identity.user_id == user.id
    assert identity.access_token == "gho_second"
    assert identity.scope == "read:user,user:email"
  end

  test "a magic link finds the user created by OAuth", %{conn: conn} do
    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "77", email: "ADA@example.com", email_verified: true, name: "Ada"},
               %{},
               auto_signup: true
             )

    conn =
      MagicLink.sign_in(conn, %{"email" => "Ada@Example.com", "name" => "Someone Else"},
        send_magic_link: fn token ->
          send(self(), {:token, token})
        end
      )

    assert redirected_to(conn) == "/users/log-in"
    assert_received {:token, token}
    assert {:ok, query} = AuthKit.UserToken.verify_magic_link_token_query(token)
    assert {%{id: id}, _stored} = Repo.one(query)
    assert id == user.id
    assert Repo.aggregate(User, :count) == 1
  end

  test "maps Google claims through Auth2.oauth_profile" do
    claims = %{
      "sub" => "google-sub-1",
      "email" => "Ada@Example.com",
      "email_verified" => "true",
      "name" => "Ada Lovelace",
      "picture" => "https://example.com/ada.png"
    }

    assert Auth2.oauth_profile(claims) == %{
             identity: "google-sub-1",
             email: "Ada@Example.com",
             email_verified: true,
             name: "Ada Lovelace",
             avatar_url: "https://example.com/ada.png"
           }

    refute Auth2.oauth_profile(%{"email_verified" => "false"}).email_verified
    refute Auth2.oauth_profile(%{"email_verified" => false}).email_verified

    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "google",
               Auth2.oauth_profile(claims),
               %{access_token: "ya29.test", id_token: "header.payload.sig"},
               auto_signup: true
             )

    assert user.email == "ada@example.com"
    assert user.name == "Ada Lovelace"
    assert user.avatar_url == "https://example.com/ada.png"
    assert user.email_confirmed_at

    identity = Repo.get_by!(Identity, provider: "google", identity: "google-sub-1")
    assert identity.user_id == user.id
    assert identity.access_token == "ya29.test"
    assert identity.id_token == "header.payload.sig"
    refute identity.scope
  end

  test "a blank name returns a changeset and writes nothing" do
    assert {:error, %Ecto.Changeset{} = changeset} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "blank", email: "ada@example.com", email_verified: true, name: "  "},
               %{},
               auto_signup: true
             )

    assert {"can't be blank", _} = changeset.errors[:name]
    assert Repo.aggregate(User, :count) == 0
    assert Repo.aggregate(Identity, :count) == 0
  end

  test "two identities from the same provider both sign in" do
    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "gh-1", email: "ada@example.com", email_verified: true, name: "Ada"},
               %{access_token: "token-1"},
               auto_signup: true
             )

    assert {:ok, linked} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "gh-2", email: "Ada@Example.com", email_verified: true, name: "Ada"},
               %{access_token: "token-2"}
             )

    assert linked.id == user.id

    assert {:ok, _} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "gh-1", email: "other@example.com", email_verified: false, name: "X"},
               %{access_token: "token-1b"}
             )

    assert {:ok, _} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "gh-2", email: "other@example.com", email_verified: false, name: "Y"},
               %{access_token: "token-2b"}
             )

    first = Repo.get_by!(Identity, provider: "github", identity: "gh-1")
    second = Repo.get_by!(Identity, provider: "github", identity: "gh-2")
    assert first.user_id == user.id
    assert second.user_id == user.id
    assert first.access_token == "token-1b"
    assert second.access_token == "token-2b"
    assert Repo.aggregate(User, :count) == 1
    assert Repo.aggregate(Identity, :count) == 2
  end

  test "duplicate provider and identity returns a changeset" do
    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "github",
               %{identity: "same", email: "ada@example.com", email_verified: true, name: "Ada"},
               %{access_token: "token-a"},
               auto_signup: true
             )

    other = Fixtures.user_fixture(%{email: "other@example.com"})

    assert {:error, changeset} =
             Auth.link_identity(%{
               user_id: other.id,
               provider: "github",
               identity: "same",
               access_token: "token-b"
             })

    assert {"has already been taken", _} = changeset.errors[:identity]
    assert Repo.get_by!(Identity, provider: "github", identity: "same").user_id == user.id
    refute Repo.get_by(Identity, user_id: other.id, provider: "github")
  end

  test "lower(email) constraint rejects a case-only duplicate through the user changeset" do
    user = Fixtures.user_fixture(%{email: "ada@example.com"})

    exception =
      assert_raise Ecto.InvalidChangesetError, fn ->
        Auth.create_user(%{email: "Ada@Example.com", name: "Other"})
      end

    assert {"has already been taken", _opts} = exception.changeset.errors[:email]
    assert Repo.get(User, user.id)
    assert Repo.aggregate(User, :count) == 1
  end
end
