defmodule AuthKit.PasswordResetTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.SignIn
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity

  test "emails a reset token only when the user exists", %{conn: conn} do
    {user, _password} = Fixtures.user_with_password_fixture()

    conn =
      SignIn.request_password_reset(conn, %{"email" => String.upcase(user.email)},
        send_reset_password: fn token -> send(self(), {:token, token}) end
      )

    assert_received {:token, token}
    assert redirected_to(conn) == "/users/log-in"
    assert {:ok, query} = AuthKit.UserToken.verify_email_token_query(token, "reset_password")
    assert Repo.one(query)

    conn =
      SignIn.request_password_reset(build_conn(), %{"email" => "missing@example.com"},
        send_reset_password: fn token -> send(self(), {:token, token}) end
      )

    refute_received {:token, _}
    assert redirected_to(conn) == "/users/log-in"
  end

  test "reset sets the password, confirms the email, and expires other sessions", %{conn: conn} do
    {user, old_password} = Fixtures.user_with_password_fixture()
    other_session = Auth.generate_session_token(user)
    token = Auth.generate_email_token(user, "reset_password")

    conn = SignIn.reset_password(conn, %{"token" => token, "password" => "newpassword1"})

    signed_in = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert signed_in.id == user.id
    assert signed_in.email_confirmed_at
    assert redirected_to(conn) == "/"
    refute Auth.fetch_user_by_session_token(other_session)

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, "newpassword1")
    refute Auth.valid_password?(identity, old_password)

    assert_raise AuthKit.Auth.HttpError, "Invalid token", fn ->
      SignIn.reset_password(build_conn(), %{"token" => token, "password" => "newpassword1"})
    end

    {confirmed, old_password} = Fixtures.confirmed_user_with_password_fixture()
    confirmed_at = confirmed.email_confirmed_at
    token = Auth.generate_email_token(confirmed, "reset_password")

    conn =
      SignIn.reset_password(build_conn(), %{"token" => token, "password" => "newpassword2"})

    signed_in = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert signed_in.email_confirmed_at == confirmed_at

    identity = Repo.get_by!(Identity, user_id: confirmed.id, provider: "credential")
    assert Auth.valid_password?(identity, "newpassword2")
    refute Auth.valid_password?(identity, old_password)
  end

  test "a short password does not consume the reset token", %{conn: conn} do
    {user, password} = Fixtures.user_with_password_fixture()
    token = Auth.generate_email_token(user, "reset_password")

    assert_raise AuthKit.Auth.HttpError, fn ->
      SignIn.reset_password(conn, %{"token" => token, "password" => "short"})
    end

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, password)

    SignIn.reset_password(conn, %{"token" => token, "password" => "newpassword1"})
    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, "newpassword1")
  end
end
