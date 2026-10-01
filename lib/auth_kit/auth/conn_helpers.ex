defmodule AuthKit.Auth.ConnHelpers do
  @doc """
  function the get conn and return conn
  """

  import Plug.Conn
  import Plug.CSRFProtection

  # Make the remember me cookie valid for 60 days.
  # If you want bump or reduce this value, also change
  # the token expiry itself in UserToken.
  @max_age 60 * 60 * 24 * 60
  @remember_me_cookie "_auth_kit_web_user_remember_me"
  @remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]

  # This function renews the session ID and erases the whole
  # session to avoid fixation attacks. If there is any data
  # in the session you may want to preserve after log in/log out,
  # you must explicitly fetch the session data before clearing
  # and then immediately set it after clearing, for example:
  #
  #     defp renew_session(conn) do
  #       preferred_locale = get_session(conn, :preferred_locale)
  #
  #       conn
  #       |> configure_session(renew: true)
  #       |> clear_session()
  #       |> put_session(:preferred_locale, preferred_locale)
  #     end
  #
  def renew_session(conn) do
    delete_csrf_token()

    user_return_to = get_session(conn, :user_return_to)

    conn
    |> configure_session(renew: true)
    |> clear_session()
    |> put_session(:user_return_to, user_return_to)
  end

  def ensure_user_token(conn) do
    if token = get_session(conn, :user_token) do
      {token, conn}
    else
      conn = fetch_cookies(conn, signed: [@remember_me_cookie])

      if token = conn.cookies[@remember_me_cookie] do
        {token, put_token_in_session(conn, token)}
      else
        {nil, conn}
      end
    end
  end

  def put_token_in_session(conn, token) do
    conn
    |> put_session(:user_token, token)
    |> put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
  end

  def maybe_write_remember_me_cookie(conn, token, %{"remember_me" => remember_me})
      when remember_me in [true, "true"] do
    put_resp_cookie(conn, @remember_me_cookie, token, @remember_me_options)
  end

  def maybe_write_remember_me_cookie(conn, _token, _params) do
    conn
  end

  @doc """
  Sends a 302 redirect to a local path. Replaces `Phoenix.Controller.redirect/2`.
  """
  def redirect(conn, to: to) do
    conn
    |> put_resp_header("location", validate_local_url!(to))
    |> put_resp_content_type("text/html")
    |> send_resp(302, "")
  end

  # Same check as Phoenix: reject protocol-relative URLs such as "//evil.com"
  # so `:to` can never send the user to another site.
  defp validate_local_url!("//" <> _ = to), do: raise_invalid_url!(to)
  defp validate_local_url!("/\\" <> _ = to), do: raise_invalid_url!(to)
  defp validate_local_url!("/" <> _ = to), do: to
  defp validate_local_url!(to), do: raise_invalid_url!(to)

  defp raise_invalid_url!(to) do
    raise ArgumentError, "the :to option in redirect expects a path but was #{inspect(to)}"
  end
end
