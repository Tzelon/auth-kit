defmodule AuthKit.ChangePasswordTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.SignIn
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity

  test "updates the password, keeps this session, and drops the others", %{conn: conn} do
    {user, password} = Fixtures.user_with_password_fixture()
    token = Auth.generate_session_token(user)
    other = Auth.generate_session_token(user)
    reset = Auth.generate_email_token(user, "reset_password")

    conn =
      conn
      |> put_session(:user_token, token)
      |> SignIn.change_password(%{
        "current_password" => password,
        "password" => "newpassword1"
      })

    assert get_session(conn, :user_token) == token
    assert Auth.fetch_user_by_session_token(token).id == user.id
    refute Auth.fetch_user_by_session_token(other)
    assert redirected_to(conn) == "/"

    assert {:ok, query} = AuthKit.UserToken.verify_email_token_query(reset, "reset_password")
    refute Repo.one(query)

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, "newpassword1")
    refute Auth.valid_password?(identity, password)
  end

  test "rejects a missing session and a wrong current password", %{conn: conn} do
    assert_raise AuthKit.Auth.HttpError, "Not signed in", fn ->
      SignIn.change_password(conn, %{
        "current_password" => "password123",
        "password" => "newpassword1"
      })
    end

    {user, password} = Fixtures.user_with_password_fixture()
    token = Auth.generate_session_token(user)
    other = Auth.generate_session_token(user)
    conn = put_session(conn, :user_token, token)

    assert_raise AuthKit.Auth.HttpError, "Invalid password", fn ->
      SignIn.change_password(conn, %{
        "current_password" => "wrongpass1",
        "password" => "newpassword1"
      })
    end

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, password)
    assert Auth.fetch_user_by_session_token(token)
    assert Auth.fetch_user_by_session_token(other)
  end
end
