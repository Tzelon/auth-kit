# Tenants

The first slice is implemented in `AuthKit.Tenants`: tenants, members, invitations, the active tenant on the session, and the `owner`, `admin`, and `member` roles. Custom roles, dynamic roles, and teams are not built yet.

Better Auth's organization plugin, renamed. A tenant is a shared workspace a user can belong to. Sign-in stays global: email, phone, and provider identity still identify one user, and a tenant is a membership on top of that user.

AuthKit does not grow an HTTP client or a plugin registry for this. The host owns the tables, the routes, and the invitation email. `AuthKit.Tenants` is the context that creates rows, checks roles, and records which tenant a session is working in.

## Names

| Better Auth | AuthKit |
| --- | --- |
| organization | tenant |
| member | tenant member |
| invitation | tenant invitation |
| organizationRole | tenant role |
| activeOrganizationId | `active_tenant_id` on the session token |
| team | team, still nested inside a tenant |

## Shape

Follow the same split as identities and user tokens. Field macros define the columns AuthKit reads. The host writes the schema module and the migration. Operations live in `AuthKit.Tenants`.

Tenant config is optional. An app that never sets it keeps compiling, and `AuthKit.Tenants` raises a clear error if called. `AuthKit.Config` keeps requiring `:user`, `:identity`, and `:user_token`.

```elixir
config :auth_kit,
  tenant: MyApp.Tenant,
  tenant_member: MyApp.TenantMember,
  tenant_invitation: MyApp.TenantInvitation
```

```elixir
defmodule MyApp.Tenant do
  use Ecto.Schema
  use AuthKit.Tenant

  schema "tenants" do
    auth_kit_tenant_fields()
    timestamps()
  end
end

defmodule MyApp.TenantMember do
  use Ecto.Schema
  use AuthKit.TenantMember

  schema "tenant_members" do
    auth_kit_tenant_member_fields()
    timestamps()
  end
end

defmodule MyApp.TenantInvitation do
  use Ecto.Schema
  use AuthKit.TenantInvitation

  schema "tenant_invitations" do
    auth_kit_tenant_invitation_fields()
    timestamps()
  end
end
```

The session token gains the active tenant only when the host asks for it:

```elixir
schema "users_tokens" do
  auth_kit_user_token_fields()
  auth_kit_active_tenant_field()
end
```

`auth_kit_user_token_fields/0` stays as it is. Existing apps do not gain a column they have not migrated.

### Columns

`tenants`

- `name` string, required
- `slug` string, required, unique, lowercase `[a-z0-9]+(?:-[a-z0-9]+)*`
- `logo` string, optional
- `metadata` map, default `%{}`

`tenant_members`

- `tenant_id` belongs_to tenant, required
- `user_id` belongs_to user, required
- `role` `{:array, :string}`, default `["member"]`
- unique on `(tenant_id, user_id)`

`tenant_invitations`

- `tenant_id` belongs_to tenant, required
- `email` string, required
- `role` `{:array, :string}`, required
- `status` enum `pending | accepted | rejected | canceled`, default `pending`
- `token` binary, the hashed invitation secret
- `expires_at` utc datetime
- `inviter_id` belongs_to user, required

`users_tokens`, via `auth_kit_active_tenant_field/0`

- `active_tenant_id` belongs_to tenant, optional

Roles are a list of strings. One member can hold `["admin", "billing"]`. Permission checks pass when any of those roles grants the action.

Extra columns are ordinary Ecto fields on the host schema. `create_tenant/2` and `update_tenant/2` cast the columns above. A host that stores more passes a changeset function in the options (`:changeset`) and AuthKit runs that on the struct before insert or update.

## What a session means

A new session leaves `active_tenant_id` empty. `set_active_tenant/2` sets it to a tenant the user belongs to, or clears it with `nil`. Two sessions for the same user can sit in different tenants. Deleting a tenant nulls every token still pointing at it.

`get_tenant/1` and `get_full_tenant/1` use the session's active tenant when no id or slug is passed.

## Roles

Three built-in roles:

| Role | Can |
| --- | --- |
| `owner` | Everything, including deleting the tenant and appointing another owner |
| `admin` | Everything except deleting the tenant and changing who the owner is |
| `member` | Read tenant, member, and invitation data |

The user who creates a tenant becomes `owner`. `:creator_role` can switch that to `"admin"`.

Default statement:

```elixir
%{
  tenant: [:update, :delete],
  member: [:create, :update, :delete],
  invitation: [:create, :cancel]
}
```

`AuthKit.Tenants.permit?/3` takes a member (or their role list), a resource, and an action. The owner check for "changing who the owner is" is separate from the statement: removing the last owner, or replacing the last owner's role with something that does not include `"owner"`, returns `{:error, :last_owner}`.

A later slice lets the host replace or extend this statement in config. Replacing `owner`, `admin`, or `member` replaces that role's grants, so the host includes the default actions they still want.

## Invitations

The link secret is a random token stored hashed, the same construction as a magic link. The invitation id is not the secret. `send_invitation` receives the raw token once.

```elixir
AuthKit.Tenants.invite(tenant, inviter, %{
  email: "ada@example.com",
  role: ["member"],
  send_invitation: fn invitation, token ->
    Mail.deliver(invitation.email, token)
  end
})
```

Accept, reject, and fetch-by-token require a signed-in user whose email matches the invitation, with `email_confirmed_at` set. The invitation is still `pending` and `expires_at` is in the future. Accepting inserts a member with the invitation's role and marks the invitation `accepted`.

Inviting an email that has no user yet is allowed. That person accepts after they sign up and confirm their email.

Inviting a current member returns `{:error, :already_member}`. Inviting an address that already has a pending invitation returns `{:error, :already_invited}` unless `resend: true`, which rotates the token and the expiry and calls `send_invitation` again. `cancel_pending_on_reinvite: true` marks the previous pending rows `canceled` before inserting the new one.

`add_member/3` inserts a membership with no email. It still enforces the membership limit and the caller's `member: :create` permission. A provisioning call passes `actor: :system` to skip the permission check.

## Functions

All of these take the acting user, and a tenant id or the session token when the active tenant should be used. They return `{:ok, result}` or `{:error, reason}`.

| Function | Better Auth endpoint | Notes |
| --- | --- | --- |
| `create_tenant/2` | `POST /organization/create` | Creator becomes a member with `:creator_role` |
| `check_slug/1` | `POST /organization/check-slug` | `{:ok, :available}` or `{:error, :taken}` |
| `list_tenants/1` | `GET /organization/list` | Tenants the user belongs to |
| `get_tenant/2` | `GET /organization/get-organization` | Metadata only |
| `get_full_tenant/2` | `GET /organization/get-full-organization` | Tenant, members (limit), pending invitations |
| `update_tenant/3` | `POST /organization/update` | Needs `tenant: :update` |
| `delete_tenant/2` | `POST /organization/delete` | Owner only. Deletes members and invitations |
| `set_active_tenant/2` | `POST /organization/set-active` | Id or slug, or `nil` to clear |
| `invite/3` | `POST /organization/invite-member` | Needs `invitation: :create` |
| `accept_invitation/2` | `POST /organization/accept-invitation` | By raw token |
| `reject_invitation/2` | `POST /organization/reject-invitation` | By raw token |
| `cancel_invitation/3` | `POST /organization/cancel-invitation` | Needs `invitation: :cancel` |
| `get_invitation/2` | `GET /organization/get-invitation` | By raw token, invited user only |
| `list_invitations/2` | `GET /organization/list-invitations` | Members of the tenant. Ids only, no raw tokens |
| `list_user_invitations/1` | list user invitations | Pending invitations for the signed-in confirmed email |
| `list_members/2` | `GET /organization/list-members` | |
| `remove_member/3` | `POST /organization/remove-member` | Needs `member: :delete`. Last owner stays |
| `update_member_role/3` | `POST /organization/update-member-role` | Needs `member: :update` |
| `active_member/1` | `GET /organization/get-active-member` | Membership for the session's active tenant |
| `active_member_role/1` | `GET /organization/get-active-member-role` | |
| `add_member/3` | `POST /organization/add-member` | Server-side, no invitation |
| `leave_tenant/2` | `POST /organization/leave` | Last owner cannot leave |

Listing invitations returns rows without a usable secret. The raw token exists only inside `send_invitation`.

## Options

Passed per call, with defaults the host can set under `config :auth_kit, tenant_options: [...]`.

| Option | Default | Meaning |
| --- | --- | --- |
| `:allow_create` | `true` | `true`, `false`, or `fn user -> boolean end`. `true` means this user may create a tenant |
| `:tenant_limit` | `:unlimited` | Positive integer or `fn user -> non_neg_integer end`. Count of memberships |
| `:creator_role` | `"owner"` | `"owner"` or `"admin"` |
| `:membership_limit` | `100` | Positive integer or `fn user, tenant -> non_neg_integer end` |
| `:invitation_expires_in` | `48` hours | |
| `:invitation_limit` | `100` | Pending invitations in that tenant |
| `:cancel_pending_on_reinvite` | `false` | |
| `:send_invitation` | required on `invite/3` | `fn invitation, raw_token -> any end` |
| `:changeset` | none | `fn changeset, attrs -> changeset end` for host columns |

A `before_*` hook returns `:ok` or `{:ok, attrs}` to continue, or `{:error, reason}` to stop the write. `after_*` hooks run after the transaction commits.

Hooks, set per call or in `config :auth_kit, tenant_hooks: %{...}`:

- `before_create_tenant`, `after_create_tenant`
- `before_update_tenant`, `after_update_tenant`
- `before_delete_tenant`, `after_delete_tenant`
- `before_add_member`, `after_add_member`
- `before_remove_member`, `after_remove_member`
- `before_update_member_role`, `after_update_member_role`
- `before_create_invitation`, `after_create_invitation`
- `before_accept_invitation`, `after_accept_invitation`
- `before_reject_invitation`, `after_reject_invitation`
- `before_cancel_invitation`, `after_cancel_invitation`

## Later slices

These stay out of the first implementation.

**Custom static roles.** `config :auth_kit, tenant_access: [statement: ..., roles: ...]`. `permit?/3` reads that map. Unknown role names refuse the action.

**Dynamic roles.** Optional `tenant_role` schema: `tenant_id`, `name`, `permissions` map. CRUD is `create_role/3`, `update_role/3`, `delete_role/3`, `list_roles/2`, `get_role/2`. A member role string that matches a row uses that row's permissions. Built-in names still win when both exist. Deleting a role that a member still holds returns `{:error, :role_in_use}`.

**Teams.** Optional, off until `:team` and `:team_member` schemas are configured. A team belongs to one tenant. Members of a team are a subset of the tenant's members. Invitations gain an optional `team_id`. The session gains `active_team_id` through `auth_kit_active_team_field/0`. Team hooks (`before_create_team`, member add and remove, update, delete) land with this slice. Team permissions reuse the tenant role of the user; a team does not have its own role table in the first teams slice.

## Tests

Extend the SQLite sandbox with `tenants`, `tenant_members`, `tenant_invitations`, and `active_tenant_id` on `users_tokens`. Cover:

- create assigns the creator as the only owner and rejects a duplicate slug
- a member cannot update or delete; an admin cannot delete; an owner can
- the last owner cannot leave, be removed, or be demoted
- invite, resend, accept, reject, cancel, expiry, and the confirmed-email match
- accept of a token for a different email fails
- `set_active_tenant/2` rejects a tenant the user is not in, and delete clears the active id
- membership and invitation limits
- a `before_*` hook error leaves the database unchanged
