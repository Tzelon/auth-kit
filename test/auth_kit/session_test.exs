defmodule AuthKit.SessionTest do
  use AuthKit.ConnCase, async: false

  alias AuthKit.Auth
  alias AuthKit.Auth.SignIn
  alias AuthKit.Auth.SignOut
  alias AuthKit.Auth.SignUp
  alias AuthKit.Fixtures
  alias AuthKit.Test.Identity

  @remember_me_cookie "_auth_kit_web_user_remember_me"

  describe "sign_in_email/2" do
    test "starts a session and drops what was already stored", %{conn: conn} do
      {user, password} = Fixtures.user_with_password_fixture()

      conn =
        conn
        |> put_session(:to_be_removed, "value")
        |> put_session(:user_return_to, "/hello")
        |> SignIn.sign_in_email(%{"email" => user.email, "password" => password})

      assert token = get_session(conn, :user_token)
      assert Auth.fetch_user_by_session_token(token).id == user.id
      assert redirected_to(conn) == "/hello"
      refute get_session(conn, :to_be_removed)
    end

    test "writes a signed remember-me cookie", %{conn: conn} do
      {user, password} = Fixtures.user_with_password_fixture()

      conn =
        SignIn.sign_in_email(conn, %{
          "email" => user.email,
          "password" => password,
          "remember_me" => "true"
        })

      token = get_session(conn, :user_token)
      assert %{value: signed_token, max_age: 5_184_000} = conn.resp_cookies[@remember_me_cookie]
      assert signed_token != token

      conn =
        build_conn()
        |> recycle_cookies(conn)
        |> fetch_cookies(signed: [@remember_me_cookie])

      assert conn.cookies[@remember_me_cookie] == token
    end

    test "rejects a wrong password and an unknown email", %{conn: conn} do
      {user, _password} = Fixtures.user_with_password_fixture()

      for params <- [
            %{"email" => user.email, "password" => "12345678"},
            %{"email" => "missing@example.com", "password" => "password123"}
          ] do
        error =
          assert_raise AuthKit.Auth.HttpError, "Invalid email or password", fn ->
            SignIn.sign_in_email(conn, params)
          end

        assert error.status == :unauthorized
      end
    end
  end

  describe "sign_up_email/2" do
    test "creates an unconfirmed user and a session", %{conn: conn} do
      params = %{"name" => "Amos", "email" => "Amos@Sked.co", "password" => "12345678"}

      conn = SignUp.sign_up_email(conn, params)

      assert token = get_session(conn, :user_token)
      assert redirected_to(conn) == "/"

      user = Auth.fetch_user_by_session_token(token)
      assert user.email == "amos@sked.co"
      assert user.name == "Amos"
      refute user.email_confirmed_at

      identity = Repo.get_by!(Identity, user_id: user.id, provider: "credential")
      assert Auth.valid_password?(identity, "12345678")
    end

    test "rejects missing, invalid, and duplicate emails", %{conn: conn} do
      missing =
        assert_raise AuthKit.Auth.HttpError, fn ->
          SignUp.sign_up_email(conn, %{})
        end

      assert missing.status == :bad_request
      assert missing.body["email"]
      assert missing.body["password"]

      invalid =
        assert_raise AuthKit.Auth.HttpError, fn ->
          SignUp.sign_up_email(conn, %{"email" => "not valid", "password" => "short"})
        end

      assert invalid.status == :bad_request
      assert invalid.body["email"] == ["must have the @ sign and no spaces"]
      assert invalid.body["password"] == ["should be at least 8 character(s)"]

      {user, _password} = Fixtures.user_with_password_fixture()

      for email <- [user.email, String.upcase(user.email)] do
        assert_raise AuthKit.Auth.HttpError, "User already exists", fn ->
          SignUp.sign_up_email(conn, %{
            "name" => "Other",
            "email" => email,
            "password" => "password123"
          })
        end
      end
    end
  end

  describe "sign_out/1" do
    test "deletes the session token, and still redirects when already signed out", %{conn: conn} do
      {user, _password} = Fixtures.user_with_password_fixture()
      token = Auth.generate_session_token(user)

      conn =
        conn
        |> put_session(:user_token, token)
        |> put_req_cookie(@remember_me_cookie, token)
        |> fetch_cookies()
        |> SignOut.sign_out_user()

      refute get_session(conn, :user_token)
      assert %{max_age: 0} = conn.resp_cookies[@remember_me_cookie]
      assert redirected_to(conn) == "/"
      refute Auth.fetch_user_by_session_token(token)

      conn = build_conn() |> SignOut.sign_out_user()
      refute get_session(conn, :user_token)
      assert redirected_to(conn) == "/"
    end
  end
end
