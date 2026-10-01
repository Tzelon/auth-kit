defmodule AuthKit.ReproTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth.SignIn
  alias AuthKit.Auth.SignUp

  @remember_me_cookie "_auth_kit_web_user_remember_me"

  test "sign-in accepts the email in the case it was typed at sign-up", %{conn: conn} do
    SignUp.sign_up_email(conn, %{
      "name" => "Amos",
      "email" => "Amos@Sked.co",
      "password" => "12345678"
    })

    conn =
      SignIn.sign_in_email(build_conn(), %{
        "email" => "Amos@Sked.co",
        "password" => "12345678"
      })

    assert get_session(conn, :user_token)
    assert redirected_to(conn) == "/"
  end

  test "a user with no password gets a 401, not a crash", %{conn: conn} do
    parent = self()

    SignUp.sign_up_email(
      conn,
      %{"name" => "Amos", "email" => "amos@sked.co", "password" => "12345678"},
      send_confirm_email: fn token -> send(parent, {:token, token}) end
    )

    assert_received {:token, token}
    SignUp.confirm_email(build_conn(), %{"token" => token})

    error =
      assert_raise AuthKit.Auth.HttpError, "Invalid email or password", fn ->
        SignIn.sign_in_email(build_conn(), %{
          "email" => "amos@sked.co",
          "password" => "12345678"
        })
      end

    assert error.status == :unauthorized
  end

  test "an unknown email takes about as long as a wrong password", %{conn: conn} do
    SignUp.sign_up_email(conn, %{
      "name" => "Amos",
      "email" => "amos@sked.co",
      "password" => "12345678"
    })

    time = fn email ->
      {us, _} =
        :timer.tc(fn ->
          try do
            SignIn.sign_in_email(build_conn(), %{"email" => email, "password" => "wrongpass1"})
          rescue
            AuthKit.Auth.HttpError -> :ok
          end
        end)

      div(us, 1000)
    end

    known = time.("amos@sked.co")
    unknown = time.("nobody@sked.co")
    assert_in_delta known, unknown, 40
  end

  test "sign-up without a name is a 400", %{conn: conn} do
    error =
      assert_raise AuthKit.Auth.HttpError, fn ->
        SignUp.sign_up_email(conn, %{"email" => "amos@sked.co", "password" => "12345678"})
      end

    assert error.status == :bad_request
    assert error.body["name"]
  end

  test "remember_me accepts a JSON boolean", %{conn: conn} do
    SignUp.sign_up_email(conn, %{
      "name" => "Amos",
      "email" => "amos@sked.co",
      "password" => "12345678"
    })

    conn =
      SignIn.sign_in_email(build_conn(), %{
        "email" => "amos@sked.co",
        "password" => "12345678",
        "remember_me" => true
      })

    assert conn.resp_cookies[@remember_me_cookie]
  end
end
