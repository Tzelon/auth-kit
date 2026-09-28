# AuthKit

Authentication building blocks for Elixir/Plug apps: email + password sign-up and sign-in (PBKDF2-SHA256 hashing), magic links, WhatsApp sign-in, Google sign-in via OpenID Connect, and sign-out.

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

  has_many :identities, AuthKit.Models.Identity
end
```

The user token schema gets its fields from AuthKit:

```elixir
defmodule MyApp.UserToken do
  use Ecto.Schema
  use AuthKit.UserToken

  schema "users_tokens" do
    auth_kit_user_token_fields()
  end
end
```
