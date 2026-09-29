defmodule AuthKit.EmailConfirmationTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.SignUp
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity
  alias AuthKit.Test.UserToken

  test "a confirm token proves the email and drops the password set before that", %{conn: conn} do
    parent = self()

    conn =
      SignUp.sign_up_email(
        conn,
        %{"name" => "Amos", "email" => "amos@sked.co", "password" => "12345678"},
        send_confirm_email: fn token -> send(parent, {:token, token}) end
      )

    assert_received {:token, confirm_token}
    signup_session = get_session(conn, :user_token)
    user = Auth.fetch_user_by_session_token(signup_session)
    refute user.email_confirmed_at
    assert Repo.get_by(Identity, user_id: user.id, provider: "credential")

    conn = SignUp.confirm_email(build_conn(), %{"token" => confirm_token})

    confirmed = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert confirmed.id == user.id
    assert confirmed.email_confirmed_at
    refute Repo.get_by(Identity, user_id: user.id, provider: "credential")
    refute Auth.fetch_user_by_session_token(signup_session)
    assert Repo.aggregate(UserToken, :count) == 1

    conn = SignUp.confirm_email(build_conn(), %{"token" => confirm_token})
    assert redirected_to(conn) == "/users/log-in?error=INVALID_TOKEN"
  end

  test "confirming an already confirmed user keeps the password", %{conn: conn} do
    {user, password} = Fixtures.confirmed_user_with_password_fixture()
    confirmed_at = user.email_confirmed_at
    token = Auth.generate_email_token(user, "confirm")

    conn = SignUp.confirm_email(conn, %{"token" => token})

    signed_in = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert signed_in.email_confirmed_at == confirmed_at

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, password)

    conn = SignUp.confirm_email(build_conn(), %{"token" => token})
    assert redirected_to(conn) == "/users/log-in?error=INVALID_TOKEN"
  end
end
