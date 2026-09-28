defmodule AuthKitWeb.Auth.MagicLinkTest do
  alias AuthKit.Models.Identity
  alias AuthKit.Auth
  alias AuthKit.Accounts.Users
  alias AuthKit.Test.User
  alias AuthKit.Repo
  use AuthKitWeb.ConnCase, async: true

  alias AuthKit.Auth.MagicLink

  @remember_me_cookie "_auth_kit_web_user_remember_me"

  setup %{conn: conn} do
    conn =
      conn
      |> Map.replace!(:secret_key_base, AuthKitWeb.Endpoint.config(:secret_key_base))
      |> init_test_session(%{})

    %{user: Factory.insert(:user), conn: conn}
  end

  describe "sign_in/2" do
    test "create user and send token without login", %{conn: conn} do
      params = %{"name" => "Amos", "email" => "amos@sked.co", "password" => "12345678"}

      conn =
        MagicLink.sign_in(conn, params,
          send_magic_link: fn token ->
            ~p"/magic-link/verify?token=#{token}"
          end
        )

      refute get_session(conn, :user_token)
      assert redirected_to(conn) == ~p"/users/log-in"
    end

    test "verify user token", %{conn: conn} do
      params = %{"name" => "Amos", "email" => "amos@sked.co", "password" => "12345678"}

      try do
        MagicLink.sign_in(conn, params,
          send_magic_link: fn token ->
            throw(~p"/magic-link/verify?token=#{token}")
          end
        )
      catch
        path ->
          %URI{query: query} = URI.parse(path)
          %{"token" => token} = URI.decode_query(query)

          conn = MagicLink.verify(conn, %{"token" => token})

          assert token = get_session(conn, :user_token)

          user = assert Users.get_by_session_token(token)
          assert user.email_confirmed_at
      end
    end
  end
end
