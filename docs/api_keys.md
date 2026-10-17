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
| `organizationId` | `tenant_id`, stored as `active_tenant_id` |
| `lastRequest` | `last_request` |
| `expiresAt` | `expires_at` (`nil` does not expire) |
| `prefix` | `prefix` (configured prefix only, safe to display) |
| `x-api-key` | `x-api-key`, and `Authorization: Bearer` |

`revoke_api_key/2` is `delete_api_key/2`. `AuthKit.Auth` defines the same functions.

Better Auth reads the user from the session on HTTP calls. These functions take the user as the first argument.

`get_api_key/2`, `update_api_key/3`, `delete_api_key/2`, and `revoke_api_key/2` cast `id` with the token schema's primary key type. Ecto's default primary key is an integer, and `revoke_api_key(user, key.id)` works for that integer. A host that uses UUIDs sets `@primary_key {:id, :binary_id, autogenerate: true}` (and `@foreign_key_type :binary_id`) and passes the UUID string. User ids are cast with the user schema's primary key type the same way.

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

That sample uses Ecto's default integer primary key. The id you pass to get, update, delete, and revoke is that integer.

### Migration

Add these columns to the user token table (the test app uses `users_tokens`):

```elixir
alter table(:users_tokens) do
  add :name, :string
  add :prefix, :string
  add :enabled, :boolean, default: true
  add :last_request, :utc_datetime_usec
  add :tenant_scoped, :boolean, null: false, default: false
  add :updated_at, :utc_datetime_usec
end

alter table(:users_tokens) do
  add :tenant_member_id, references(:tenant_members, type: :binary_id, on_delete: :nilify_all)
end
```

`tenant_member_id` uses the host's member primary key type. The test app uses `:binary_id`.

`name` is the label. `prefix` is the configured prefix (`"pup_"`), capped at 32 characters. It is the only display fragment stored, and it never includes the generated key. `last_request` is the last successful verification. `expires_at` is already on the table and stays `nil` when the key does not expire. `updated_at` changes when the key is updated or successfully verified.

`tenant_scoped` is true when the key was created for a tenant. `tenant_member_id` is that membership row. Deleting the membership nilifies it, and a new membership does not fill it back in, so the old key stays invalid. `active_tenant_id` uses `ON DELETE SET NULL` so a session row stays valid after the tenant is deleted. A scoped API key whose `active_tenant_id` becomes `nil` does not authenticate. An unscoped key has `tenant_scoped` false and a null `active_tenant_id`, and stays valid.

The lookup uses the existing unique index on `(context, token)`.

## Create

```elixir
{:ok, api_key} =
  AuthKit.ApiKey.create_api_key(user,
    name: "ci",
    prefix: "pup_",
    expires_in: 60 * 60 * 24 * 7,
    tenant_id: tenant.id
  )

api_key.key
```

`api_key.key` is the only time the plaintext is available. Later calls return the same fields without `:key`.

`expires_in` is seconds. Omit it, or pass `nil`, to use `:default_expires_in` from config. When that is also unset, the key does not expire. Custom lifetimes must sit between 1 and 365 days unless `key_expiration` changes `min_expires_in` and `max_expires_in`.

`tenant_id` scopes the key to a tenant the user already belongs to. The owner's id stays `user_id`. The tenant id is stored in `active_tenant_id`, `tenant_scoped` is set, and `tenant_member_id` records that membership. `organization_id` is rejected.

`:organization_id`, `:permissions`, `:metadata`, `:remaining`, `:config_id`, `:refill_amount`, `:refill_interval`, `:rate_limit_enabled`, `:rate_limit_max`, and `:rate_limit_time_window` return `{:error, {:not_supported, field}}`.

## Verify, list, revoke

```elixir
%{valid: true, error: nil, key: metadata} = AuthKit.ApiKey.verify_api_key(plaintext)

{:ok, %{api_keys: keys, total: total}} =
  AuthKit.ApiKey.list_api_keys(user, limit: 20, sort_by: "createdAt", sort_direction: "desc")

{:ok, page} = AuthKit.ApiKey.list_api_keys(user, offset: 20)

{:ok, %{success: true}} = AuthKit.ApiKey.revoke_api_key(user, metadata.id)
```

`verify_api_key/2` returns `%{valid: boolean, error: nil | %{code: code, message: message}, key: metadata | nil}`. Invalid keys use `error.code` `"INVALID_API_KEY"`, `"KEY_DISABLED"`, `"KEY_EXPIRED"`, or `"USER_NOT_MEMBER_OF_TENANT"`. A successful check writes `last_request`. An expired key is deleted. Two verifies of the same expired key both return invalid. Neither raises if the row was already deleted.

`list_api_keys/2` can filter with `:tenant_id`, and page with `:limit` and `:offset`. An offset without a limit returns the remaining rows. Sort fields are `createdAt`, `name`, and `expiresAt`.

`get_api_key/2` and `update_api_key/3` also omit the secret. Update accepts `:name` and `:enabled`.

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
    key_expiration: [
      default_expires_in: nil,
      disable_custom_expires_time: false,
      min_expires_in: 1,
      max_expires_in: 365
    ]
  ]
```

`:default_key_length` is the number of random letters after the prefix. The alphabet is `a-zA-Z`, matching Better Auth's default generator. `:default_expires_in` is seconds. Better Auth's reference page describes that plugin option in milliseconds; the create API and this library use seconds, which is what `expiresIn` means on `createApiKey`.

`:maximum_prefix_length` defaults to 32 and is capped there. The stored `prefix` is that configured string, never a slice of the generated key. A `starting_characters_config` `characters_length` longer than the key does not copy the secret into the row.

## Tenants

A scoped key verifies only while `tenant_member_id` still points at the membership from create time. `remove_member/3` and `leave_tenant/2` delete that user's keys for the tenant. A raw delete of the membership nilifies `tenant_member_id`. Adding the user again creates a new membership and does not revive the key. `Tenants.delete_tenant/2` deletes every key scoped to the tenant before the tenant row goes away.

`active_tenant_id` is `ON DELETE SET NULL`. A session that pointed at the tenant stays valid with that column cleared. A raw `Repo.delete(tenant)` does the same to the column on an API key, but the key's `tenant_scoped` flag stays true, so `verify_api_key/2` rejects it instead of treating it as an unscoped user key. Unscoped keys stay valid.

The owner is always the user. A key the tenant itself owns, per-key permissions, and request quotas are proposed in `docs/contributing/proposals/001-api-key-ownership-and-limits.md`.
