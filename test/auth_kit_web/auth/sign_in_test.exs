defmodule AuthKitWeb.Auth.UserSignInTest do
  use AuthKitWeb.ConnCase, async: true

  alias AuthKit.Models.Identity
  alias AuthKit.Auth
  alias AuthKit.Accounts.Users
  alias AuthKit.Test.User
  alias AuthKit.Repo

  alias AuthKit.Auth.SignIn
  alias AuthKit.Auth.SignOut
  alias AuthKit.Auth.SignUp

  @remember_me_cookie "_auth_kit_web_user_remember_me"

  setup %{conn: conn} do
    conn =
      conn
      |> Map.replace!(:secret_key_base, AuthKitWeb.Endpoint.config(:secret_key_base))
      |> init_test_session(%{})

    %{user: Factory.insert(:user), conn: conn}
  end

  describe "sign_in_email/2" do
    test "stores the user token in the session", %{conn: conn, user: user} do
      credential_identity = Enum.find(user.identities, &(&1.provider == "credential"))

      conn =
        SignIn.sign_in_email(conn, %{
          "email" => user.email,
          "password" => credential_identity.clear_password
        })

      assert token = get_session(conn, :user_token)
      assert redirected_to(conn) == ~p"/"
      assert Users.get_by_session_token(token)
    end

    test "throw error on wrong password", %{conn: conn, user: user} do
      error =
        assert_raise AuthKit.Auth.HttpError, fn ->
          SignIn.sign_in_email(conn, %{"email" => user.email, "password" => "12345678"})
        end

      assert %AuthKit.Auth.HttpError{
               status: :unauthorized,
               body: "Invalid email or password",
               headers: %{},
               status_code: 401
             } = error
    end

    test "clears everything previously stored in the session", %{conn: conn, user: user} do
      credential_identity = Enum.find(user.identities, &(&1.provider == "credential"))

      conn =
        conn
        |> put_session(:to_be_removed, "value")
        |> SignIn.sign_in_email(%{
          "email" => user.email,
          "password" => credential_identity.clear_password
        })

      refute get_session(conn, :to_be_removed)
    end

    test "redirects to the configured path", %{conn: conn, user: user} do
      credential_identity = Enum.find(user.identities, &(&1.provider == "credential"))

      conn =
        conn
        |> put_session(:user_return_to, "/hello")
        |> SignIn.sign_in_email(%{
          "email" => user.email,
          "password" => credential_identity.clear_password
        })

      assert redirected_to(conn) == "/hello"
    end

    test "writes a cookie if remember_me is configured", %{conn: conn, user: user} do
      credential_identity = Enum.find(user.identities, &(&1.provider == "credential"))

      conn =
        conn
        |> fetch_cookies()
        |> SignIn.sign_in_email(%{
          "email" => user.email,
          "password" => credential_identity.clear_password,
          "remember_me" => "true"
        })

      assert get_session(conn, :user_token) == conn.cookies[@remember_me_cookie]

      assert %{value: signed_token, max_age: max_age} = conn.resp_cookies[@remember_me_cookie]
      assert signed_token != get_session(conn, :user_token)
      assert max_age == 5_184_000
    end
  end

  describe "sign_out/1" do
    test "erases session and cookies", %{conn: conn, user: user} do
      user_token = Auth.generate_session_token(user)

      conn =
        conn
        |> put_session(:user_token, user_token)
        |> put_req_cookie(@remember_me_cookie, user_token)
        |> fetch_cookies()
        |> SignOut.sign_out_user()

      refute get_session(conn, :user_token)
      refute conn.cookies[@remember_me_cookie]
      assert %{max_age: 0} = conn.resp_cookies[@remember_me_cookie]
      assert redirected_to(conn) == ~p"/"

      refute Users.get_by_session_token(user_token)
    end

    test "works even if user is already logged out", %{conn: conn} do
      conn = conn |> fetch_cookies() |> Auth.SignOut.sign_out_user()
      refute get_session(conn, :user_token)
      assert %{max_age: 0} = conn.resp_cookies[@remember_me_cookie]
      assert redirected_to(conn) == ~p"/"
    end
  end

  describe "sign_up_email/2" do
    test "success: it inserts a user in the db and returns the user", %{conn: conn} do
      params = %{"name" => "Amos", "email" => "amos@sked.co", "password" => "12345678"}

      conn = SignUp.sign_up_email(conn, params)

      assert token = get_session(conn, :user_token)
      assert redirected_to(conn) == ~p"/"

      # check db is updated
      user = assert Users.get_by_session_token(token)
      identity = assert Repo.get_by!(Identity, user_id: user.id, provider: "credential")

      user_from_db = Repo.get(User, user.id)
      assert user_from_db == user

      identity_fields = ["password"]

      for {param_field, expected} <- params, param_field not in identity_fields do
        schema_field = String.to_atom(param_field)
        actual = Map.get(user_from_db, schema_field)

        assert actual == expected,
               "Values did not match for field #{param_field}\nexpected #{inspect(expected)}\nactual: #{inspect(actual)}"
      end

      assert identity.clear_password == nil

      assert user_from_db.inserted_at == user_from_db.updated_at
    end

    test "requires email and password to be set", %{conn: conn} do
      error =
        assert_raise AuthKit.Auth.HttpError, fn ->
          SignUp.sign_up_email(conn, %{})
        end

      assert %AuthKit.Auth.HttpError{
               status: :bad_request,
               body: %{
                 "email" => ["is required"],
                 "password" => ["is required"]
               },
               headers: %{},
               status_code: 400
             } =
               error
    end

    test "validates email and password when given", %{conn: conn} do
      error =
        assert_raise AuthKit.Auth.HttpError, fn ->
          SignUp.sign_up_email(conn, %{"email" => "not valid", "password" => "short"})
        end

      assert %AuthKit.Auth.HttpError{
               status: :bad_request,
               body: %{
                 "email" => ["must match pattern ^[^\\s]+@[^\\s]+$"],
                 "password" => ["must be at least 8"]
               },
               headers: %{},
               status_code: 400
             } =
               error
    end

    test "validates email uniqueness", %{conn: conn, user: user} do
      assert_raise AuthKit.Auth.HttpError, "User already exists", fn ->
        SignUp.sign_up_email(conn, %{
          "email" => user.email,
          "password" => Faker.String.base64(12)
        })
      end

      # Now try with the upper cased email too, to check that email case is ignored.
      assert_raise AuthKit.Auth.HttpError, "User already exists", fn ->
        SignUp.sign_up_email(conn, %{
          "email" => String.upcase(user.email),
          "password" => Faker.String.base64(12)
        })
      end
    end
  end
end
