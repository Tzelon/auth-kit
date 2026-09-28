defmodule AuthKit.Auth.SignOut do
  require Logger

  import AuthKit.Auth.ConnHelpers
  import Plug.Conn

  alias AuthKit.Auth

  @remember_me_cookie "_auth_kit_web_user_remember_me"

  @doc """
  Logs the user out.

  It clears all session data for safety. See renew_session.
  """
  def sign_out_user(conn) do
    user_token = get_session(conn, :user_token)

    if user_token == nil do
      Logger.error("Failed to get session")
    end

    user_token && Auth.delete_session_token(user_token)

    conn
    |> renew_session()
    |> delete_resp_cookie(@remember_me_cookie)
    |> redirect(to: "/")
  end
end
