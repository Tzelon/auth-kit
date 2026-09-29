# AuthKit

Authentication building blocks for Elixir/Plug apps: email + password sign-up and sign-in (PBKDF2-SHA256 hashing), email confirmation, password reset, magic links, WhatsApp sign-in, Google sign-in via OpenID Connect, bearer sessions, and sign-out.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `auth_kit` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:auth_kit, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/auth_kit>.


## Configuration

```elixir
config :auth_kit,
  repo: MyApp.Repo,
  # Your schemas (required).
  user: MyApp.User,
  identity: MyApp.Identity,
  user_token: MyApp.UserToken
```

`:user` is read at compile time. After changing it, run
`mix deps.compile auth_kit --force`.

A custom user schema needs these fields and association.
`use AuthKit.UserSchema` fails the build if any are missing:

```elixir
use AuthKit.UserSchema

schema "users" do
  field :email, :string
  field :name, :string
  field :avatar_url, :string
  field :phone_number, :string
  field :phone_verified_at, :utc_datetime
  field :email_confirmed_at, :utc_datetime

  has_many :identities, MyApp.Identity
end
```

The identity and user token schemas get their fields from AuthKit:

```elixir
defmodule MyApp.Identity do
  use Ecto.Schema
  use AuthKit.Identity

  schema "identities" do
    auth_kit_identity_fields()
    timestamps()
  end
end

defmodule MyApp.UserToken do
  use Ecto.Schema
  use AuthKit.UserToken

  schema "users_tokens" do
    auth_kit_user_token_fields()
  end
end
```

## Email confirmation and passwords

Password sign-up accepts `send_confirm_email: fn token -> ... end`.
`AuthKit.Auth.SignUp.confirm_email/2` checks that `"confirm"` token and calls
`AuthKit.Auth.confirm_user_email/1`. On an account that was not yet confirmed
this removes the password and every token, then starts a new session.

`AuthKit.Auth.SignIn.request_password_reset/3` accepts
`send_reset_password: fn token -> ... end`. `reset_password/2` stores the new
password, expires every token, and confirms the email. `change_password/2`
checks the current password, updates the credential, and expires every token
except the session making the request.

## Tenants

A tenant is a workspace a user belongs to. Sign-in stays global. Configure `tenant`, `tenant_member`, and `tenant_invitation`, and add `auth_kit_active_tenant_field/0` to the user token schema when sessions should remember a tenant. The host sends invitation email through the `:send_invitation` callback. See `AuthKit.Tenants` and `docs/tenants.md`.

## Bearer sessions

Session tokens are raw bytes. `AuthKit.UserToken.encode_session_token/1`
base64url-encodes one for a header. `plug AuthKit.Auth.Bearer` reads
`Authorization: Bearer <token>` and assigns `:current_user`.

