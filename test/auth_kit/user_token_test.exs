defmodule AuthKit.UserTokenTest do
  use AuthKit.DataCase, async: false

  alias AuthKit.Fixtures
  alias AuthKit.Test.UserToken
  alias AuthKit.UserToken, as: Tokens

  test "email tokens verify only for their own context and only while fresh" do
    user = Fixtures.user_fixture()

    {confirm, confirm_record} = Tokens.build_email_token(user, "confirm")
    {reset, reset_record} = Tokens.build_email_token(user, "reset_password")
    Repo.insert!(confirm_record)
    Repo.insert!(reset_record)

    assert {:ok, query} = Tokens.verify_email_token_query(confirm, "confirm")
    assert {%{id: id}, stored} = Repo.one(query)
    assert id == user.id

    assert {:ok, query} = Tokens.verify_email_token_query(reset, "reset_password")
    assert {%{id: ^id}, _token} = Repo.one(query)

    assert {:ok, query} = Tokens.verify_email_token_query(confirm, "reset_password")
    refute Repo.one(query)
    assert Tokens.verify_email_token_query("!!!", "confirm") == :error

    past = DateTime.utc_now() |> DateTime.add(-8, :day) |> DateTime.truncate(:second)

    Repo.update_all(from(t in UserToken, where: t.id == ^stored.id), set: [inserted_at: past])

    assert {:ok, query} = Tokens.verify_email_token_query(confirm, "confirm")
    refute Repo.one(query)
  end
end
