defmodule AuthKit.OAuthSignInTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
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

  test "runs Google-shaped claims through sign_in_with_oauth" do
    claims = %{
      "sub" => "google-sub-1",
      "email" => "Ada@Example.com",
      "email_verified" => "true",
      "name" => "Ada Lovelace",
      "picture" => "https://example.com/ada.png"
    }

    assert {:ok, user} =
             Auth.sign_in_with_oauth(
               "google",
               %{
                 identity: claims["sub"],
                 email: claims["email"],
                 email_verified: claims["email_verified"] in [true, "true"],
                 name: claims["name"],
                 avatar_url: claims["picture"]
               },
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

  test "lower(email) unique index rejects another user that differs only by case" do
    user = Fixtures.user_fixture(%{email: "ada@example.com"})

    assert {:error, changeset} =
             %User{}
             |> Ecto.Changeset.cast(%{email: "Ada@Example.com", name: "Other"}, [:email, :name])
             |> Ecto.Changeset.validate_required([:email, :name])
             |> Ecto.Changeset.unique_constraint(:email, name: :users_lower_email_index)
             |> Repo.insert()

    assert {"has already been taken", _opts} = changeset.errors[:email]
    assert Repo.get(User, user.id)
  end
end
