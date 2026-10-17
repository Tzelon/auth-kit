# Device authorization

OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) for CLI login, on the same `users_tokens` table as sessions and API keys. Better Auth's [device authorization plugin](https://better-auth.com/docs/plugins/device-authorization) is the shape of the HTTP API. The credential the CLI stores is an AuthKit API key, not a browser session.

## Why one row, and why an API key

A grant is one `users_tokens` row with context `"device"`. Approval, denial, the poll interval, and expiry all change that row. A second table, or a second token row for the user code, would have to stay in lockstep with it. The user code lives in `user_code` on the same row so approval can find the device code.

Columns added by `auth_kit_device_fields/0`:

| Column | Role |
| --- | --- |
| `user_code` | SHA-256 of the canonical user code. Unique. Null on every other context. |
| `status` | `pending`, `approved`, or `denied`. |
| `interval` | Minimum seconds between polls of a pending grant. Starts at 5 and grows by 5 after `slow_down`. |

Columns already on the table, reused:

| Column | Role on a device grant |
| --- | --- |
| `token` | SHA-256 of the device code. The existing `(context, token)` unique index is the lookup. |
| `name` | Client id, shown on the approval page. |
| `sent_to` | Optional scope string. |
| `user_id` | Approving user. Null while pending, unless the code was pre-bound. |
| `active_tenant_id` | Tenant passed to approve. The issued API key is scoped to it. |
| `tenant_scoped` | True when approval stored a tenant. |
| `last_request` | Last poll that was accepted. Drives `slow_down`. |
| `expires_at` | When the codes stop working. |
| `updated_at` | Last status or interval change. |

`user_id` and `active_tenant_id` are the linkage to the user and the tenant. There is no extra linkage column. Dropped Better Auth API-key fields (`permissions`, `metadata`, `remaining`, and the rest) are not re-added. Scope is display-only. Per-key permissions are still the deferred API-key work.

Both codes are returned once, in plaintext. The database stores SHA-256. Lookups compare the digest with `Plug.Crypto.secure_compare/2`. The user code alphabet is `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no `0`, `O`, `1`, or `I`), eight characters, shown as `ABCD-EFGH`. The canonical form is the uppercase letters and digits with separators removed. Dashes, spaces, and letter case are ignored when the user types the code.

Success mints a user API key through `AuthKit.ApiKey.create_api_key/2` and deletes the device row in the same transaction. The CLI stores that key. `plug AuthKit.Auth.Bearer` already accepts it as `Authorization: Bearer <key>` or `x-api-key: <key>`. `AuthKit.Device.credential_headers/1` builds both. The key is not a base64 session token. Session tokens are for browsers. A CLI key is long-lived, listed, and revoked with the API-key functions without signing the user out of the browser. The default key does not expire. Set `api_key_expires_in` or the API key `:default_expires_in` when it should.

`change_password` and `reset_password` delete every token for the user, including API keys issued by this flow.

## Names

| RFC 8628 / Better Auth | AuthKit |
| --- | --- |
| `POST /device/code`, `device.code` | `AuthKit.Device.request_device_authorization/1` |
| `POST /device/token`, `device.token` | `poll_device_token/2` |
| `GET /device`, `device()` | `get_device_authorization/2` |
| `POST /device/approve`, `device.approve` | `approve_device_authorization/3` |
| `POST /device/deny`, `device.deny` | `deny_device_authorization/2` |
| `authorization_pending` | `{:error, :authorization_pending}` |
| `slow_down` | `{:error, :slow_down}` |
| `expired_token` | `{:error, :expired_token}` |
| `access_denied` | `{:error, :access_denied}` |
| `invalid_grant` | `{:error, :invalid_grant}` |
| `invalid_client` | `{:error, :invalid_client}` |
| `access_token` | plaintext API key, returned once |

`AuthKit.Auth` defines the same functions. `code_body/1`, `token_body/1`, and `error_body/1` turn those results into RFC JSON with string keys.

`slow_down` is returned only while the grant is still pending. After the user approves, the next poll returns the key even if it arrives inside the interval, so the CLI does not wait out the spacing the user just spent approving.

## Schema

```elixir
defmodule MyApp.UserToken do
  use Ecto.Schema
  use AuthKit.UserToken

  schema "users_tokens" do
    auth_kit_user_token_fields()
    auth_kit_active_tenant_field()
    auth_kit_api_key_fields()
    auth_kit_device_fields()
  end
end
```

`auth_kit_active_tenant_field/0` is required only when approve passes `tenant_id:`. `auth_kit_api_key_fields/0` is required because the poll creates an API key and the grant reuses those columns.

### Migration

API key columns are in `docs/api_keys.md`. Add the device columns next to them:

```elixir
alter table(:users_tokens) do
  add :user_code, :binary
  add :status, :string
  add :interval, :integer
end

create unique_index(:users_tokens, [:user_code])
```

`interval` is quoted by Ecto. Other contexts leave `user_code` null, and the unique index allows those nulls. The lookup for the device code stays on the existing unique index `(context, token)`.

## Host endpoints

The library does not ship a router. Mount these on the authentication server. Code and token are public. Approve, deny, and the verification read require a signed-in user. Send `Cache-Control: no-store` on every response. Serve them over HTTPS outside local development.

| Method | Path | Auth | Calls |
| --- | --- | --- | --- |
| `POST` | `/device/code` | no | `request_device_authorization/1` |
| `POST` | `/device/token` | no | `poll_device_token/2` |
| `GET` | `/device` | yes | `get_device_authorization/2` |
| `POST` | `/device/approve` | yes | `approve_device_authorization/3` |
| `POST` | `/device/deny` | yes | `deny_device_authorization/2` |

```elixir
def code(conn, params) do
  result =
    AuthKit.Device.request_device_authorization(
      client_id: params["client_id"],
      scope: params["scope"]
    )

  json(conn, code_status(result), AuthKit.Device.code_body(result))
end

def token(conn, params) do
  result =
    AuthKit.Device.poll_device_token(params["device_code"],
      grant_type: params["grant_type"],
      client_id: params["client_id"]
    )

  json(conn, token_status(result), AuthKit.Device.token_body(result))
end

def show(conn, params) do
  user_code = params["user_code"] || params["userCode"]
  result = AuthKit.Device.get_device_authorization(conn.assigns.current_user, user_code)
  json(conn, code_status(result), result_body(result))
end

def approve(conn, params) do
  user_code = params["user_code"] || params["userCode"]

  result =
    AuthKit.Device.approve_device_authorization(conn.assigns.current_user, user_code,
      tenant_id: conn.assigns[:current_tenant_id]
    )

  json(conn, code_status(result), result_body(result))
end

defp code_status({:ok, _}), do: 200
defp code_status({:error, _}), do: 400

defp token_status({:ok, _}), do: 200
defp token_status({:error, _}), do: 400
```

`GET /device` does not claim the code. Approve is what binds the user. Show the client id and scope from `get_device_authorization/2` and make the user confirm the code matches the device. Warn them not to approve a code that arrived in a message.

The approval page can read `user_code` from the query string. `verification_uri_complete` is that URL.

## Calls

```elixir
{:ok, grant} =
  AuthKit.Device.request_device_authorization(client_id: "puppi", scope: "openid")

grant.device_code
grant.user_code
grant.verification_uri
grant.verification_uri_complete
grant.expires_in
grant.interval
```

`grant_type` on the poll is `AuthKit.Device.grant_type/0`, the string `urn:ietf:params:oauth:grant-type:device_code`.

```elixir
{:ok, view} = AuthKit.Device.get_device_authorization(user, user_code)
{:ok, _} = AuthKit.Device.approve_device_authorization(user, user_code, tenant_id: tenant.id)
{:ok, _} = AuthKit.Device.deny_device_authorization(user, user_code)

case AuthKit.Device.poll_device_token(device_code,
       grant_type: AuthKit.Device.grant_type(),
       client_id: "puppi"
     ) do
  {:ok, token} ->
    token.access_token
    AuthKit.Device.credential_headers(token)

  {:error, :authorization_pending} ->
    :continue

  {:error, :slow_down} ->
    :wait_longer

  {:error, reason} ->
    reason
end
```

`token.access_token` is the only copy of the API key. `token.api_key_id` is the id `revoke_api_key/2` accepts. `token.expires_in` is nil when the key does not expire. A second poll of the same device code is `:invalid_grant`.

`user_id:` on the code request pre-binds the grant. Only that user can approve or deny it. Pass it from the server, not from the device.

A missing client id is `:invalid_request`. A client id outside `allowed_clients` is `:invalid_client`. A poll whose client id does not match the one stored on the grant is `:invalid_grant`. A wrong `grant_type` is `:unsupported_grant_type`.

Expired and consumed rows are removed with `Repo.delete_all/1`. Two polls of the same expired code both return `:expired_token` or `:invalid_grant`. Neither raises `Ecto.StaleEntryError`.

## Config

```elixir
config :auth_kit,
  device_authorization: [
    verification_uri: "/device",
    verification_uri_complete: true,
    expires_in: 1800,
    interval: 5,
    user_code_length: 8,
    allowed_clients: ["puppi"],
    api_key_name: nil,
    api_key_prefix: "pup_",
    api_key_expires_in: nil
  ]
```

`:verification_uri` is returned as `verification_uri`. It can be a path (`"/device"`) or an absolute URL. `:verification_uri_complete` defaults to true and appends `?user_code=`. Set it to false to omit that field.

`:expires_in` is the code lifetime in seconds. Default `1800` (30 minutes). `:interval` is the starting poll spacing in seconds. Default `5`. Minimum `1`. After `slow_down` the stored interval increases by 5, up to 300. `:user_code_length` defaults to 8 and must be from 4 to 32.

`:allowed_clients` is nil (any client id), a list of ids, or `fn client_id -> boolean end`. Set it in production.

`:api_key_name` is the label stored on the issued key. When it is nil, the client id is used if it fits the API key name length, otherwise `"cli"`. `:api_key_prefix` and `:api_key_expires_in` are passed through to `create_api_key/2`. `:api_key_expires_in` is seconds. Nil means the API key default, which is no expiry unless `api_key: [key_expiration: [default_expires_in: ...]]` is set. Custom key lifetimes still have to sit inside the API key min and max (1 to 365 days by default).

## CLI

1. `POST /device/code` with `client_id`.
2. Show `user_code` and open `verification_uri_complete` or `verification_uri`.
3. Poll `POST /device/token` with `grant_type`, `device_code`, and `client_id`. Wait `interval` seconds between polls. On `slow_down`, add 5 seconds.
4. Store `access_token`. Send it as `Authorization: Bearer` or `x-api-key`.

The bearer plug assigns `:current_user` and `:current_api_key`. A key scoped at approval also assigns `:current_tenant_id`.

## Deferred

- OAuth provider access tokens, refresh tokens, JWT, and a registered client table. This flow issues a first-party API key.
- RFC 8707 `resource`.
- A claim step on `GET /device`. Approve binds the user. Pre-bind with `user_id:` when the server already knows who the device belongs to.
- Custom device-code and user-code generators.
- A rate limit on the verification page. Poll spacing and `slow_down` are enforced.
- Enforcing `scope` on the API key. The approval page shows it. Permissions on keys are still deferred.
