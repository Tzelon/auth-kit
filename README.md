# AuthKit

Authentication building blocks for Elixir/Plug apps: email + password sign-up and sign-in (PBKDF2-SHA256 hashing), email confirmation, password reset, magic links, WhatsApp sign-in, Google sign-in via OpenID Connect, GitHub sign-in, bearer sessions, and sign-out.

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
  user_token: MyApp.UserToken,
  # 32 bytes, standard base64. AuthKit does not boot without it.
  token_encryption_key: System.get_env("AUTH_KIT_TOKEN_ENCRYPTION_KEY")
```

`:user` is read at compile time. After changing it, run
`mix deps.compile auth_kit --force`.

`access_token`, `refresh_token`, and `id_token` are encrypted with
AES-256-GCM before they are written. A loaded identity struct still has
the plaintext. A stored value with no `ak1:` prefix is legacy plaintext;
the next write of that field stores ciphertext. No data migration is
required. Generate a key with `openssl rand -base64 32`.

User emails are stored trimmed and lowercased. `AuthKit.Auth.fetch_user_by_email/2`
and OAuth account linking both normalize the address that way, then compare
it to `lower(email)`. The `users_lower_email_index` index below is unchanged.

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

The host app must add these unique indexes. Account linking is unsafe without them.

```elixir
create unique_index(:users, ["lower(email)"], name: :users_lower_email_index)

create unique_index(:identities, [:provider, :identity],
         name: :identities_provider_identity_index)
```

`AuthKit.Auth` maps a conflict on either index to a changeset error.
Rows that already store the same address in a different letter case, or
two identity rows with the same provider and identity, make the indexes
fail to build. Merge those rows before adding them. AuthKit does not ship
a migration that rewrites existing rows, and it does not ship a host migration.

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

## Social sign-in

```elixir
config :auth_kit, :google,
  client_id: System.get_env("GOOGLE_CLIENT_ID"),
  client_secret: System.get_env("GOOGLE_CLIENT_SECRET"),
  redirect_uri: "https://example.com/auth/google/callback"

config :auth_kit, :github,
  client_id: System.get_env("GITHUB_CLIENT_ID"),
  client_secret: System.get_env("GITHUB_CLIENT_SECRET"),
  redirect_uri: "https://example.com/auth/github/callback"
```

`:token_url` overrides the access-token URL for GitHub Enterprise Server.
`:user_url` overrides the user profile URL for GitHub Enterprise Server.
`:emails_url` overrides the email list URL for GitHub Enterprise Server.

Google and GitHub authorization requests use PKCE (S256). Store the whole
session map from `authorize_url/1` and pass it back to `callback/2`. It
includes the code verifier and the time the state was issued. A callback
older than `:oauth_state_ttl` seconds (default 600), or a session from
before that map included a verifier, fails with the same `401` as any
other OAuth failure. Google ID tokens are checked, including the RS256
signature, against `https://www.googleapis.com/oauth2/v3/certs`. The certs
are cached for the `Cache-Control` max-age, and an unknown `kid` is fetched
once more.

`AuthKit.Auth.sign_in_with_oauth(provider, profile, token_attrs \\ %{}, opts \\ [])`
returns `{:ok, user}` or `{:error, reason}`.

`:auto_signup` defaults to `false`. An identity for `{provider, identity}`
returns that user and refreshes its tokens. Otherwise `:email_verified` must
be `true`. Any other value returns `{:error, :email_not_verified}` and writes
nothing. A verified email is trimmed and downcased, then looked up with
`lower(email)` in the database.
A match links the identity and confirms the email. With `:auto_signup` false
and no match, the result is `{:error, :user_not_found}` and nothing is written.
`auto_signup: true` creates the user, links the identity, and confirms the email.

Google claims map as `identity: claims["sub"]`, `email: claims["email"]`,
`email_verified: claims["email_verified"] in [true, "true"]`,
`name: claims["name"]`, `avatar_url: claims["picture"]`.

GitHub uses an address from `/user/emails` only when that address is both
primary and verified.

## Email confirmation and passwords

Password sign-up accepts `send_confirm_email: fn token -> ... end`.
`AuthKit.Auth.SignUp.confirm_email/2` checks that `"confirm"` token and calls
`AuthKit.Auth.confirm_user_email/1`. On an account that was not yet confirmed
this removes the password and every credential token, then starts a new session.
The device-authorization attempt counter is left in place.

`AuthKit.Auth.SignIn.request_password_reset/3` accepts
`send_reset_password: fn token -> ... end`. `reset_password/2` stores the new
password, expires every credential token, and confirms the email. `change_password/2`
checks the current password, updates the credential, and expires every credential
token except the session making the request. Neither clears the device-authorization
attempt counter.

## Tenants

A tenant is a workspace a user belongs to. Sign-in stays global. Configure `tenant`, `tenant_member`, and `tenant_invitation`, and add `auth_kit_active_tenant_field/0` to the user token schema when sessions should remember a tenant. The host sends invitation email through the `:send_invitation` callback. See `AuthKit.Tenants` and `docs/tenants.md`.

## Bearer sessions

Session tokens are raw bytes. `AuthKit.UserToken.encode_session_token/1`
base64url-encodes one for a header. `plug AuthKit.Auth.Bearer` reads
`Authorization: Bearer <token>` and assigns `:current_user`. The same plug
accepts an API key in that header, or in `x-api-key`.

## API keys

Long-lived credentials for scripts and CI, following Better Auth's
[API key plugin](https://better-auth.com/docs/plugins/api-key).
`AuthKit.ApiKey.create_api_key/2` (also on `AuthKit.Auth`) returns the
plaintext key once. The database stores only its SHA-256 hash on
`users_tokens` with context `"api"`. `list_api_keys/2` and `get_api_key/2`
return name, prefix, timestamps, expiry, and last use, never the secret.
`prefix` is the configured prefix only. `delete_api_key/2` and
`revoke_api_key/2` remove one key. `verify_api_key/2` checks it. Those
calls accept the token schema's primary key, including an integer id.

Add `auth_kit_api_key_fields/0` to the user token schema and run the
migration in `docs/api_keys.md`. Pass `tenant_id:` to scope a key to a
tenant the user belongs to. Removing that membership
revokes those keys. Deleting the tenant, including a raw delete of the
tenant row, stops the scoped key from authenticating. Session tokens only
have `active_tenant_id` cleared. A scoped key sets `:current_tenant_id` on
the bearer plug.

A key owned by the tenant, per-key permissions, and request quotas are
proposed in
`docs/contributing/proposals/001-api-key-ownership-and-limits.md`.
Passing those options returns `{:error, {:not_supported, field}}`.

## Device authorization

CLI login uses the OAuth 2.0 Device Authorization Grant (RFC 8628).
`AuthKit.Device.request_device_authorization/1` returns a `device_code`,
a short `user_code`, a `verification_uri`, and the poll `interval`.
A signed-in user approves that code with `approve_device_authorization/3`.
`poll_device_token/2` then returns an API key once, in `access_token`.
The CLI stores that key and sends it to `plug AuthKit.Auth.Bearer`.

Pending polls return `:authorization_pending`. Polling faster than
`interval` returns `:slow_down`. Denial is `:access_denied`. An expired
code is `:expired_token`. See `docs/device_flow.md` for the endpoints a
host mounts and the config options.

