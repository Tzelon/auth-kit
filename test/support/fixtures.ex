defmodule AuthKit.Fixtures do
  @moduledoc false

  alias AuthKit.Auth

  def unique_email, do: "user#{System.unique_integer([:positive])}@example.com"

  def user_fixture(attrs \\ %{}) do
    Auth.create_user(%{
      email: attrs[:email] || unique_email(),
      name: attrs[:name] || "Test User",
      avatar_url: attrs[:avatar_url],
      phone_number: attrs[:phone_number]
    })
  end

  def user_with_password_fixture(attrs \\ %{}) do
    password = attrs[:password] || "password123"
    user = user_fixture(attrs)

    Auth.link_identity(%{
      user_id: user.id,
      provider: "credential",
      identity: user.id,
      password: password
    })

    {user, password}
  end

  @doc """
  A confirmed user with a password set after confirmation.

  `confirm_user_email/1` removes any password that was set while the email
  was still unconfirmed, so the credential is created afterwards.
  """
  def confirmed_user_with_password_fixture(attrs \\ %{}) do
    password = attrs[:password] || "password123"
    user = user_fixture(attrs)
    {:ok, user, _} = Auth.confirm_user_email(user)

    Auth.link_identity(%{
      user_id: user.id,
      provider: "credential",
      identity: user.id,
      password: password
    })

    {user, password}
  end
end
