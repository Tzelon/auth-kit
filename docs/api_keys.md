# API keys

Better Auth's [API key plugin](https://better-auth.com/docs/plugins/api-key), on the user token table. A key is a long-lived credential for scripts and CI. Sign-in stays on session tokens.

The plaintext is returned once from `create_api_key/2`. The row stores `SHA-256` of that string in `users_tokens.token` with context `"api"`, the same digest email tokens use. Better Auth stores `base64url(sha256)` in an `apikey` table. AuthKit keeps the raw digest so the existing binary `token` column can hold it.

## Names

| Better Auth | AuthKit |
| --- | --- |
| `createApiKey` | `AuthKit.ApiKey.create_api_key/2` |
| `verifyApiKey` | `verify_api_key/2` |
| `getApiKey` | `get_api_key/2` |
| `updateApiKey` | `update_api_key/3` |
| `deleteApiKey` | `delete_api_key/2` |
| `listApiKeys` | `list_api_keys/2` |
| `deleteAllExpiredApiKeys` | `delete_all_expired_api_keys/1` |
| `referenceId` | `reference_id` and `user_id` (the owning user) |
| `organizationId` | `organization_id` and `active_tenant_id` (optional scope) |
| `lastRequest` | `last_request` |
| `expiresAt` | `expires_at` (`nil` does not expire) |
| `start` | `start` (first characters, safe to display) |
| `prefix` | `prefix` |
| `x-api-key` | `x-api-key`, and `Authorization: Bearer` |

`revoke_api_key/2` is `delete_api_key/2`. `AuthKit.Auth` defines the same functions.

Better Auth reads the user from the session on HTTP calls. These functions take the user as the first argument.

## Schema

`auth_kit_user_token_fields/0` stays as it is. Call `auth_kit_api_key_fields/0` in the host schema when the app issues keys. A scoped key also needs `auth_kit_active_tenant_field/0`.

```elixir
defmodule MyApp.UserToken do
  use Ecto.Schema
  use AuthKit.UserToken

  schema "users_tokens" do
    auth_kit_user_token_fields()
    auth_kit_active_tenant_field()
    auth_kit_api_key_fields()
  end
end
```

### Migration

Add these columns to the user token table (the test app uses `users_tokens`):

```elixir
alter table(:users_tokens) do
  add :name, :string
  add :prefix, :string
  add :start, :string
  add :config_id, :string
  add :enabled, :boolean, default: true
  add :last_request, :utc_datetime_usec
  add :metadata, :map
  add :permissions, :map
  add :remaining, :integer
  add :updated_at, :utc_datetime_usec
end
```

`name` is the label. `prefix` is the configured prefix (`"pup_"`). `start` is the first characters of the full key, including the prefix (6 by default), so a list can show which key is which. `config_id` defaults to `"default"`. `last_request` is the last successful verification. `remaining` is a use cap; `nil` means no cap. `expires_at` is already on the table and stays `nil` when the key does not expire. `metadata` and `permissions` are maps.

The lookup uses the existing unique index on `(context, token)`.

## Create

```elixir
{:ok, api_key} =
  AuthKit.ApiKey.create_api_key(user,
    name: "ci",
    prefix: "pup_",
    expires_in: 60 * 60 * 24 * 7,
    permissions: %{projects: ["read"]},
    tenant_id: tenant.id
  )

api_key.key
```

`api_key.key` is the only time the plaintext is available. Later calls return the same fields without `:key`.

`expires_in` is seconds. Omit it, or pass `nil`, to use `:default_expires_in` from config. When that is also unset, the key does not expire. Custom lifetimes must sit between 1 and 365 days unless `key_expiration` changes `min_expires_in` and `max_expires_in`.

`tenant_id` and `organization_id` are the same option. The user must already be a member. The key's `reference_id` stays the user. The tenant is the scope (`active_tenant_id`), which is this library's reading of Better Auth's organization id on a user-owned key.

`metadata` is rejected until config enables it, matching Better Auth's `enableMetadata: false` default.

`:refill_amount`, `:refill_interval`, `:rate_limit_enabled`, `:rate_limit_max`, and `:rate_limit_time_window` return `{:error, {:not_supported, field}}`.

## Verify, list, revoke

```elixir
%{valid: true, error: nil, key: metadata} =
  AuthKit.ApiKey.verify_api_key(plaintext, permissions: %{projects: ["read"]})

{:ok, %{api_keys: keys, total: total}} =
  AuthKit.ApiKey.list_api_keys(user, limit: 20, sort_by: "createdAt", sort_direction: "desc")

{:ok, %{success: true}} = AuthKit.ApiKey.revoke_api_key(user, metadata.id)
```

`verify_api_key/2` returns the Better Auth result map. Invalid keys are `valid: false` with `error.code` of `"INVALID_API_KEY"`, `"KEY_DISABLED"`, `"KEY_EXPIRED"`, `"KEY_NOT_FOUND"` (missing permission), `"USAGE_EXCEEDED"`, or `"USER_NOT_MEMBER_OF_ORGANIZATION"`. A successful check writes `last_request` and decrements `remaining` when it is a number. An expired key, and a key whose remaining count is already 0, is deleted.

`list_api_keys/2` can filter with `:config_id`, `:tenant_id`, or `:organization_id`, and page with `:limit` and `:offset`. Sort fields are `createdAt`, `name`, and `expiresAt`.

`get_api_key/2` and `update_api_key/3` also omit the secret. Update accepts `:name`, `:enabled`, `:remaining`, `:metadata`, `:permissions`, and `:expires_in` (`nil` clears the expiry).

`delete_all_expired_api_keys/1` removes expired API keys. Create, list, and verify call it with a 10 second cooldown. Pass `force: true` to run it immediately. Sessions are left alone.

## Bearer

```elixir
plug AuthKit.Auth.Bearer
```

The plug assigns `:current_user`. For an API key it also assigns `:current_api_key` (metadata, no secret) and `:current_tenant_id` when the key is scoped.

`x-api-key` wins when it is present, including over a bearer session on the same request. Otherwise `Authorization: Bearer` is tried as a session token and then as an API key, so existing session clients keep working.

```elixir
config :auth_kit, api_key: [api_key_headers: ["x-api-key"]]
```

## Config

```elixir
config :auth_kit,
  api_key: [
    default_prefix: "pup_",
    default_key_length: 64,
    require_name: false,
    enable_metadata: true,
    default_permissions: %{projects: ["read"]},
    starting_characters_config: [should_store: true, characters_length: 6],
    key_expiration: [
      default_expires_in: nil,
      disable_custom_expires_time: false,
      min_expires_in: 1,
      max_expires_in: 365
    ]
  ]
```

`:default_key_length` is the number of random letters after the prefix. The alphabet is `a-zA-Z`, matching Better Auth's default generator. `:default_expires_in` is seconds. Better Auth's reference page describes that plugin option in milliseconds; the create API and this library use seconds, which is what `expiresIn` means on `createApiKey`.

`:default_permissions` may be a map or a function of the user.

## Tenants

A scoped key verifies only while the user is still a member of `active_tenant_id`. `remove_member/3` and `leave_tenant/2` delete that user's keys for the tenant. Deleting the tenant deletes every key scoped to it. Session tokens on that tenant only have `active_tenant_id` cleared. Unscoped keys stay valid.

Better Auth can store organization-owned keys whose `referenceId` is the organization (`references: "organization"`). AuthKit does not do that yet. The owner is always the user.

## Not in this slice

- Rate limiting (Better Auth turns it on by default: 10 requests per day)
- Refill (`refillAmount` / `refillInterval`)
- Secondary storage and multiple configuration objects (`config_id` is stored and can filter, and there is one option set)
- Organization-owned keys
- `enableSessionForAPIKeys` beyond the bearer assigns above
- Disabling the hash, or a custom key generator
- Permission wildcards from Better Auth's access plugin. Verification requires each requested action to be listed on the key
