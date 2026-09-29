defmodule AuthKit.Auth.Bearer do
  @moduledoc """
  Loads the current user from an `Authorization: Bearer` header.

  Put it in a pipeline:

      plug AuthKit.Auth.Bearer

  The header value is a session token from `AuthKit.UserToken.encode_session_token/1`.
  The plug assigns `:current_user` to that user, or `nil` when the header is
  missing or the token does not match a live session.
  """

  @behaviour Plug

  import Plug.Conn

  alias AuthKit.Auth
  alias AuthKit.UserToken

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    assign(conn, :current_user, user_from_bearer(conn))
  end

  defp user_from_bearer(conn) do
    with ["Bearer " <> encoded] <- get_req_header(conn, "authorization"),
         {:ok, token} <- UserToken.decode_session_token(encoded) do
      Auth.fetch_user_by_session_token(token)
    else
      _ -> nil
    end
  end
end
