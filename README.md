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
  # Your user schema (required).
  user: MyApp.User
```

`:user` is read at compile time. After changing it, run
`mix deps.compile auth_kit --force`.

A custom user schema needs these fields and association:

```elixir
schema "users" do
  field :email, :string
  field :name, :string
  field :avatar_url, :string
  field :phone_number, :string
  field :phone_number_verified, :boolean
  field :confirmed_at, :utc_datetime

  has_many :identities, AuthKit.Models.Identity
end
```
