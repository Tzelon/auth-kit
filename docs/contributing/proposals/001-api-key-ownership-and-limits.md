# 001 — API key ownership, permissions, and limits

Status: proposal. The current API key slice does not implement this.

## What exists

An API key is a `users_tokens` row with context `"api"`, owned by one user (`user_id`). `create_api_key/2`, `list_api_keys/2`, and `revoke_api_key/2` all take that user. `AuthKit.Auth.Bearer` assigns `:current_user` from it.

`tenant_id:` is a scope, stored in `active_tenant_id`, with `tenant_scoped` set. That is the same column a session uses for "which tenant this credential is working in." The user must be a member at create time. Removing the membership deletes those keys. A key with no `tenant_id` has `tenant_scoped` false and keeps working.

Options this proposal covers are rejected with `{:error, {:not_supported, field}}`. They are not stored. A caller cannot believe a limit or a permission is in force when the row has nowhere to put it.

## Why the tenant is not the owner

A tenant-owned key would still be valid after every member who created or listed it had left. List, revoke, and the bearer plug would need a new rule: which members may see the key, and which user (if any) `:current_user` is.

The token table does not have a second owner. `user_id` is the principal those functions already use. Reusing `active_tenant_id` as "the tenant owns this key" would collide with sessions, where a null `active_tenant_id` means "no tenant selected" and the session remains a user session. API keys already use `tenant_scoped` so a nil `active_tenant_id` after a raw tenant delete does not look like an unscoped user key.

So this slice keeps one owner, the user, and treats the tenant as a scope that ends with the membership.

A later design can add tenant-owned keys as a separate case:

- The row records the tenant as the owner, and `user_id` as the member who created it.
- Listing and revoking require a membership permission, not "this row's user_id is me."
- Bearer assigns the tenant. It does not assign `:current_user` from `user_id`, because that user may have left.
- Membership removal does not delete the key. Deleting the tenant does.

Until that exists, pass `tenant_id:` for a user key scoped to a tenant. `organization_id` is rejected.

## Why permissions are not on the key

Verify would have to decide, on every request, whether the key's resource-to-actions map covers the actions the host asked for. Hosts do not share one permission vocabulary, and the token schema has no column for the map. Rejecting `:permissions` avoids a check that always succeeds because nothing was stored.

When this is built:

- The key stores `%{resource => [action]}`.
- `verify_api_key/2` accepts `permissions:` and succeeds only when every requested action is present on the key.
- A verify that omits `permissions:` does not consult the map.

## Why rate limits and refill are not enforced

Both need counters updated on every successful verify: a window, a request count, and for refill a last-refill time plus an amount. That wants columns this migration does not add (`name`, `prefix`, `enabled`, `last_request`, `tenant_scoped`, `updated_at`). Doing the math without those columns would reset on every request.

When this is built, verify decrements or refills in the same write as `last_request`, and a key that is over its quota fails without authenticating. `:remaining` is the simple form of that quota (a count, no clock). `:refill_amount` and `:refill_interval` restore the count on a schedule. `:rate_limit_max` and `:rate_limit_time_window` cap requests inside a window. `:metadata` and `:config_id` can land in the same migration if a host needs them on the row; they are rejected today for the same reason, there is no column.
