defmodule AuthKit.BearerTest do
  use AuthKit.ConnCase, async: false

  import Ecto.Query

  alias AuthKit.Auth
  alias AuthKit.Auth.Bearer
  alias AuthKit.Fixtures
  alias AuthKit.Test.UserToken
  alias AuthKit.UserToken, as: Tokens

  test "assigns the user from a live base64url bearer token", %{conn: conn} do
    user = Fixtures.user_fixture()
    token = Auth.generate_session_token(user)
    encoded = Tokens.encode_session_token(token)

    authed =
      conn
      |> put_req_header("authorization", "Bearer " <> encoded)
      |> Bearer.call([])

    assert authed.assigns.current_user.id == user.id

    refused = [
      conn,
      put_req_header(conn, "authorization", "Bearer !!!"),
      put_req_header(conn, "authorization", "Basic " <> encoded),
      put_req_header(conn, "authorization", "Bearer " <> Tokens.encode_session_token("nope"))
    ]

    for conn <- refused do
      assert Bearer.call(conn, []).assigns.current_user == nil
    end

    past = DateTime.utc_now() |> DateTime.add(-1, :second)
    Repo.update_all(from(t in UserToken, where: t.user_id == ^user.id), set: [expires_at: past])

    expired =
      conn
      |> put_req_header("authorization", "Bearer " <> encoded)
      |> Bearer.call([])

    assert expired.assigns.current_user == nil
  end
end
