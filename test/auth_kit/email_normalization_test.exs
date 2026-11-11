defmodule AuthKit.EmailNormalizationTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.SignIn
  alias AuthKit.Fixtures
  alias AuthKit.Test.User

  test "writes a trimmed lowercase email and finds it again" do
    user = Auth.create_user(%{email: "  ADA@Example.com  ", name: "Ada"})
    assert user.email == "ada@example.com"
    assert Auth.fetch_user_by_email("Ada@example.com").id == user.id
    assert Auth.fetch_user_by_email("\tADA@example.com\n").id == user.id
  end

  test "fetch_user_by_email matches a legacy mixed-case row" do
    user = Fixtures.user_fixture(%{email: "ada@example.com"})

    Repo.query!("UPDATE users SET email = ? WHERE email = ?", [
      "Ada@Example.com",
      "ada@example.com"
    ])

    assert Auth.fetch_user_by_email("  ADA@example.com ").id == user.id
    assert Repo.get!(User, user.id).email == "Ada@Example.com"
  end

  test "oauth linking uses the same normalization against lower(email)" do
    user = Fixtures.user_fixture(%{email: "ada@example.com"})

    Repo.query!("UPDATE users SET email = ? WHERE email = ?", [
      "Ada@Example.com",
      "ada@example.com"
    ])

    assert {:ok, linked} =
             Auth.sign_in_with_oauth(
               "github",
               %{
                 identity: "gh-norm",
                 email: "  ADA@example.com ",
                 email_verified: true,
                 name: "Ada"
               },
               %{access_token: "gho_norm"}
             )

    assert linked.id == user.id
    assert Repo.aggregate(User, :count) == 1
  end

  test "password sign-in finds the account when the case differs", %{conn: conn} do
    {user, password} = Fixtures.user_with_password_fixture(%{email: "ada@example.com"})

    conn =
      SignIn.sign_in_email(conn, %{"email" => "ADA@Example.com", "password" => password})

    assert redirected_to(conn) == "/"
    assert Auth.fetch_user_by_session_token(get_session(conn, :user_token)).id == user.id
  end
end
