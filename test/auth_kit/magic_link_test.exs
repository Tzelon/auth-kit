defmodule AuthKit.MagicLinkTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.MagicLink
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity
  alias AuthKit.Test.User

  test "emails a login token without starting a session", %{conn: conn} do
    email = "amos@sked.co"

    conn =
      MagicLink.sign_in(conn, %{"name" => "Amos", "email" => "Amos@Sked.co"},
        send_magic_link: fn token ->
          send(self(), {:token, token})
        end
      )

    assert_received {:token, token}
    assert {:ok, query} = AuthKit.UserToken.verify_magic_link_token_query(token)
    assert {%{email: ^email}, _stored} = Repo.one(query)
    refute get_session(conn, :user_token)
    assert redirected_to(conn) == "/users/log-in"

    MagicLink.sign_in(build_conn(), %{"name" => "Amos", "email" => email},
      send_magic_link: fn _token -> :ok end
    )

    assert Repo.aggregate(User, :count) == 1
  end

  test "verify signs the user in and confirms an unproven email", %{conn: conn} do
    {user, _password} = Fixtures.user_with_password_fixture(%{email: "amos@sked.co"})
    token = Auth.generate_login_token(user)

    conn = MagicLink.verify(conn, %{"token" => token})

    assert session = get_session(conn, :user_token)
    signed_in = Auth.fetch_user_by_session_token(session)
    assert signed_in.id == user.id
    assert signed_in.email_confirmed_at
    refute Repo.get_by(Identity, user_id: user.id, provider: "credential")

    conn =
      MagicLink.verify(build_conn(), %{
        "token" => token,
        "callback_url" => "/users/log-in"
      })

    assert redirected_to(conn) == "/users/log-in?error=INVALID_TOKEN"
    refute get_session(conn, :user_token)
  end

  test "verify leaves the password in place when the email is already confirmed", %{conn: conn} do
    {user, password} = Fixtures.confirmed_user_with_password_fixture()
    confirmed_at = user.email_confirmed_at
    token = Auth.generate_login_token(user)

    conn = MagicLink.verify(conn, %{"token" => token})

    signed_in = Auth.fetch_user_by_session_token(get_session(conn, :user_token))
    assert signed_in.email_confirmed_at == confirmed_at

    identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
    assert Auth.valid_password?(identity, password)
  end
end
