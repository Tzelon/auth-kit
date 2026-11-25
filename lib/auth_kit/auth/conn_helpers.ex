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

  # Renews the session id and clears every key so a fixation attack
  # cannot keep data from before sign-in or sign-out. Read anything that
  # must survive before calling this, then write it back after.
  #
  # `:user_return_to` is not written back. The caller that redirects there
  # reads it first. Copying it forward made a later sign-in reuse a path
  # from an earlier visit, including after sign-out.
  def renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
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
