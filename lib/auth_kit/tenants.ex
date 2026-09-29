defmodule AuthKit.Tenants do
  @moduledoc """
  Tenants, memberships, and invitations.

  A tenant is a workspace a user belongs to. Sign-in stays global: email,
  phone, and provider identity still find one user. The active tenant is
  stored on the session token, so two sessions can sit in different tenants.

  Configure the host schemas:

      config :auth_kit,
        tenant: MyApp.Tenant,
        tenant_member: MyApp.TenantMember,
        tenant_invitation: MyApp.TenantInvitation

  Add `auth_kit_active_tenant_field/0` to the user token schema so a session
  can remember its tenant. The host owns the tables, the routes, and the
  invitation email (`:send_invitation`).

  Roles are `owner`, `admin`, and `member`. `permit?/3` checks the built-in
  grants. The last owner cannot leave, be removed, or be demoted, and only
  an owner can appoint or remove an owner.

  Options passed to a function override `config :auth_kit, tenant_options: [...]`.
  Hooks are a map of functions. A `before_*` hook returns `:ok`, `{:ok, map}`
  (merged into the payload), or `{:error, reason}`. `after_*` hooks run after
  the write commits. Configure defaults with `config :auth_kit, tenant_hooks: %{...}`,
  and override per call with `hooks: %{...}`.

  `:changeset` is `fn changeset, attrs -> changeset end`, applied after
  AuthKit's casts so the host can persist extra columns.
  """

  import Ecto.Changeset
  import Ecto.Query

  alias AuthKit.Repo
  alias AuthKit.Tenants.Access
  alias Ecto.Multi

  @slug ~r/^[a-z0-9]+(?:-[a-z0-9]+)*$/
  @email ~r/^[^\s]+@[^\s]+$/

  @doc """
  Creates a tenant and adds `user` as a member.

  The creator's role is `:creator_role`, `"owner"` unless set to `"admin"`.
  Returns `{:ok, %{tenant: tenant, member: member}}`.
  """
  def create_tenant(user, attrs, opts \\ []) when is_map(attrs) and is_list(opts) do
    ensure!()

    with :ok <- allow_create(user, opts),
         :ok <- within_tenant_limit(user, opts),
         {:ok, payload} <- before_hook(opts, :before_create_tenant, %{attrs: attrs, user: user}),
         {:ok, role} <- creator_role(opts),
         {:ok, %{tenant: tenant, member: member}} <-
           insert_tenant(user, payload.attrs, role, opts) do
      after_hook(opts, :after_create_tenant, %{tenant: tenant, member: member, user: user})
      {:ok, %{tenant: tenant, member: member}}
    end
  end

  @doc """
  Returns `{:ok, :available}` or `{:error, :taken}`. An unusable slug is
  `{:error, :invalid_slug}`.
  """
  def check_slug(slug) when is_binary(slug) do
    ensure!()

    slug = normalize_slug(slug)

    cond do
      not slug_ok?(slug) -> {:error, :invalid_slug}
      slug_taken?(slug) -> {:error, :taken}
      true -> {:ok, :available}
    end
  end

  def check_slug(_slug) do
    ensure!()
    {:error, :invalid_slug}
  end

  @doc """
  Lists the tenants `user` belongs to.
  """
  def list_tenants(user) do
    ensure!()

    tenants =
      from(t in tenant_schema(),
        join: m in assoc(t, :members),
        where: m.user_id == ^user.id,
        order_by: [asc: t.slug]
      )
      |> Repo.all()

    {:ok, tenants}
  end

  @doc """
  Returns the tenant metadata.

  Pass `tenant_id:` or `slug:`, or `session:` to use that session's active
  tenant. The user must be a member.
  """
  def get_tenant(user, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, tenant, _member} <- member_tenant(user, opts) do
      {:ok, tenant}
    end
  end

  @doc """
  Returns `%{tenant: tenant, members: members, invitations: invitations}`.

  Members are capped by `:members_limit`, which defaults to `:membership_limit`
  (100). Invitations are the pending ones. Invitation secrets are omitted.
  """
  def get_full_tenant(user, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, tenant, _member} <- member_tenant(user, opts) do
      limit = members_limit(user, tenant, opts)

      members =
        from(m in member_schema(),
          where: m.tenant_id == ^tenant.id,
          order_by: [asc: m.user_id],
          limit: ^limit,
          preload: [:user]
        )
        |> Repo.all()

      invitations =
        pending_invitations(tenant)
        |> Enum.map(&public_invitation/1)

      {:ok, %{tenant: tenant, members: members, invitations: invitations}}
    end
  end

  @doc """
  Updates the tenant name, slug, logo, or metadata. Requires `tenant: :update`.
  """
  def update_tenant(user, attrs, opts \\ []) when is_map(attrs) and is_list(opts) do
    ensure!()

    with {:ok, tenant, member} <- member_tenant(user, opts),
         :ok <- permit(member, :tenant, :update),
         {:ok, payload} <-
           before_hook(opts, :before_update_tenant, %{
             tenant: tenant,
             attrs: attrs,
             user: user,
             member: member
           }),
         {:ok, tenant} <- save_tenant(tenant, payload.attrs, opts) do
      after_hook(opts, :after_update_tenant, %{tenant: tenant, user: user, member: member})
      {:ok, tenant}
    end
  end

  @doc """
  Deletes the tenant, its members, and its invitations. Owner only.

  Sessions that were working in the tenant have `active_tenant_id` cleared.
  """
  def delete_tenant(user, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, tenant, member} <- member_tenant(user, opts),
         :ok <- permit(member, :tenant, :delete),
         :ok <-
           before_ok(opts, :before_delete_tenant, %{tenant: tenant, user: user, member: member}),
         {:ok, _} <- delete_tenant_rows(tenant) do
      after_hook(opts, :after_delete_tenant, %{tenant: tenant, user: user, member: member})
      {:ok, tenant}
    end
  end

  @doc """
  Points the session at a tenant the user belongs to.

  `session_token` is the raw session token, or the base64url bearer value.
  `ref` is a tenant id, a slug, `%{id: id}`, `%{slug: slug}`, a tenant
  struct, or `nil` to clear the active tenant.
  """
  def set_active_tenant(session_token, ref) do
    ensure!()
    ensure_active_tenant_field!()

    with {:ok, session} <- load_session(session_token),
         {:ok, session} <- write_active_tenant(session, ref) do
      {:ok, session}
    end
  end

  @doc """
  Invites `email` into `tenant`.

  `attrs` includes `:email`, `:role`, and `:send_invitation` (`fn invitation, raw_token -> any end`).
  `resend: true` rotates the secret on the pending invitation. `cancel_pending_on_reinvite: true`
  cancels pending invitations for that email and inserts a new one.

  The raw token is passed to `:send_invitation` and is not stored.
  """
  def invite(tenant, inviter, attrs) when is_map(attrs) do
    invite(tenant, inviter, attrs, [])
  end

  def invite(tenant, inviter, attrs, opts) when is_map(attrs) and is_list(opts) do
    ensure!()

    opts = Keyword.merge(opts, hooks: Map.merge(hook_map(opts), hook_map(attrs)))

    with {:ok, tenant} <- as_tenant(tenant),
         {:ok, member} <- fetch_member(inviter, tenant),
         :ok <- permit(member, :invitation, :create),
         {:ok, email} <- normalize_email(attr(attrs, :email)),
         {:ok, role} <- normalize_roles(attr(attrs, :role)),
         :ok <- authorize_owner_grant(member, role),
         :ok <- not_already_member(tenant, email),
         send <- send_invitation(attrs, opts),
         :ok <- require_sender(send) do
      deliver_invitation(tenant, inviter, email, role, send, attrs, opts)
    end
  end

  @doc """
  Accepts an invitation token for the signed-in user.

  The user's email must match the invitation and `email_confirmed_at` must be set.
  """
  def accept_invitation(user, raw_token) when is_binary(raw_token) do
    accept_invitation(user, raw_token, [])
  end

  def accept_invitation(user, raw_token, opts) when is_binary(raw_token) and is_list(opts) do
    ensure!()

    with {:ok, invitation} <- invitation_for_user(user, raw_token),
         {:ok, tenant} <- fetch_tenant_by_id(invitation.tenant_id),
         :ok <- under_membership_limit(tenant, user, opts),
         :ok <-
           before_ok(opts, :before_accept_invitation, %{
             invitation: invitation,
             user: user,
             tenant: tenant
           }),
         {:ok, %{invitation: invitation, member: member}} <- accept_rows(invitation, user, tenant) do
      after_hook(opts, :after_accept_invitation, %{
        invitation: invitation,
        member: member,
        user: user,
        tenant: tenant
      })

      {:ok, %{invitation: public_invitation(invitation), member: member}}
    end
  end

  @doc """
  Rejects an invitation token. Same email and confirmation checks as accept.
  """
  def reject_invitation(user, raw_token) when is_binary(raw_token) do
    reject_invitation(user, raw_token, [])
  end

  def reject_invitation(user, raw_token, opts) when is_binary(raw_token) and is_list(opts) do
    ensure!()

    with {:ok, invitation} <- invitation_for_user(user, raw_token),
         {:ok, tenant} <- fetch_tenant_by_id(invitation.tenant_id),
         :ok <-
           before_ok(opts, :before_reject_invitation, %{
             invitation: invitation,
             user: user,
             tenant: tenant
           }),
         {:ok, invitation} <- set_status(invitation, :rejected) do
      after_hook(opts, :after_reject_invitation, %{
        invitation: invitation,
        user: user,
        tenant: tenant
      })

      {:ok, public_invitation(invitation)}
    end
  end

  @doc """
  Cancels a pending invitation. Requires `invitation: :cancel`.
  """
  def cancel_invitation(user, invitation_id, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, invitation} <- fetch_invitation(invitation_id),
         {:ok, tenant} <- fetch_tenant_by_id(invitation.tenant_id),
         {:ok, member} <- fetch_member(user, tenant),
         :ok <- permit(member, :invitation, :cancel),
         :ok <- pending_only(invitation),
         :ok <-
           before_ok(opts, :before_cancel_invitation, %{
             invitation: invitation,
             cancelled_by: user,
             tenant: tenant
           }),
         {:ok, invitation} <- set_status(invitation, :canceled) do
      after_hook(opts, :after_cancel_invitation, %{
        invitation: invitation,
        cancelled_by: user,
        tenant: tenant
      })

      {:ok, public_invitation(invitation)}
    end
  end

  @doc """
  Loads a pending invitation by its raw token for the invited user.
  """
  def get_invitation(user, raw_token) when is_binary(raw_token) do
    ensure!()

    with {:ok, invitation} <- invitation_for_user(user, raw_token) do
      {:ok, public_invitation(invitation)}
    end
  end

  @doc """
  Lists a tenant's invitations. Members only. Secrets are omitted.
  """
  def list_invitations(user, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, tenant, _member} <- member_tenant(user, opts) do
      invitations =
        from(i in invitation_schema(),
          where: i.tenant_id == ^tenant.id,
          order_by: [asc: i.email]
        )
        |> Repo.all()
        |> Enum.map(&public_invitation/1)

      {:ok, invitations}
    end
  end

  @doc """
  Lists pending, unexpired invitations for the user's confirmed email.
  """
  def list_user_invitations(user) do
    ensure!()

    if is_nil(user.email_confirmed_at) do
      {:error, :email_not_confirmed}
    else
      email = String.downcase(user.email || "")
      now = DateTime.utc_now()

      invitations =
        from(i in invitation_schema(),
          where:
            fragment("lower(?)", i.email) == ^email and i.status == :pending and
              i.expires_at > ^now,
          order_by: [asc: i.email]
        )
        |> Repo.all()
        |> Enum.map(&public_invitation/1)

      {:ok, invitations}
    end
  end

  @doc """
  Lists the tenant's members. The caller must be a member.
  """
  def list_members(user, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, tenant, _member} <- member_tenant(user, opts) do
      members =
        from(m in member_schema(),
          where: m.tenant_id == ^tenant.id,
          order_by: [asc: m.user_id],
          preload: [:user]
        )
        |> Repo.all()

      {:ok, members}
    end
  end

  @doc """
  Removes a member. Requires `member: :delete`. The last owner stays.
  """
  def remove_member(actor, member_id, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, target} <- fetch_member_by_id(member_id),
         {:ok, tenant} <- fetch_tenant_by_id(target.tenant_id),
         {:ok, actor_member} <- fetch_member(actor, tenant),
         :ok <- permit(actor_member, :member, :delete),
         :ok <- authorize_remove(actor_member, target),
         :ok <-
           before_ok(opts, :before_remove_member, %{member: target, user: actor, tenant: tenant}) do
      Repo.delete!(target)
      clear_active_tenant(target.user_id, tenant.id)
      after_hook(opts, :after_remove_member, %{member: target, user: actor, tenant: tenant})
      {:ok, target}
    end
  end

  @doc """
  Replaces a member's roles. Requires `member: :update`.

  Only an owner can grant or revoke `"owner"`. The last owner cannot be demoted.
  """
  def update_member_role(actor, member_id, role, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, target} <- fetch_member_by_id(member_id),
         {:ok, roles} <- normalize_roles(role),
         {:ok, tenant} <- fetch_tenant_by_id(target.tenant_id),
         {:ok, actor_member} <- fetch_member(actor, tenant),
         :ok <- permit(actor_member, :member, :update),
         :ok <- authorize_owner_change(actor_member, target, roles),
         {:ok, payload} <-
           before_hook(opts, :before_update_member_role, %{
             member: target,
             role: roles,
             user: actor,
             tenant: tenant
           }),
         {:ok, roles} <- normalize_roles(payload.role),
         {:ok, target} <- save_role(target, roles) do
      after_hook(opts, :after_update_member_role, %{
        member: target,
        previous_role: payload.member.role,
        user: actor,
        tenant: tenant
      })

      {:ok, target}
    end
  end

  @doc """
  Returns the caller's membership in the session's active tenant.
  """
  def active_member(session_token) do
    ensure!()
    ensure_active_tenant_field!()

    with {:ok, session} <- load_session(session_token),
         {:ok, tenant_id} <- active_id(session),
         {:ok, member} <- fetch_member_in(session.user_id, tenant_id) do
      {:ok, member}
    end
  end

  @doc """
  Returns the role list for `active_member/1`.
  """
  def active_member_role(session_token) do
    with {:ok, member} <- active_member(session_token) do
      {:ok, member.role}
    end
  end

  @doc """
  Adds a user to a tenant without an invitation.

  `actor` is a member with `member: :create`, or `:system` to skip that check.
  The membership limit still applies. `attrs` is `%{user_id: id, role: ["member"]}`.
  """
  def add_member(actor, tenant, attrs, opts \\ []) when is_map(attrs) and is_list(opts) do
    ensure!()

    with {:ok, tenant} <- as_tenant(tenant),
         :ok <- authorize_add(actor, tenant, attrs),
         {:ok, user} <- fetch_user(attr(attrs, :user_id)),
         {:ok, role} <- normalize_roles(attr(attrs, :role) || ["member"]),
         :ok <- under_membership_limit(tenant, user, opts),
         nil <- Repo.get_by(member_schema(), tenant_id: tenant.id, user_id: user.id),
         {:ok, payload} <-
           before_hook(opts, :before_add_member, %{
             member: %{user_id: user.id, role: role},
             user: user,
             tenant: tenant,
             actor: actor
           }),
         {:ok, role} <- normalize_roles(payload.member.role),
         {:ok, member} <- insert_member(tenant, user, role) do
      after_hook(opts, :after_add_member, %{
        member: member,
        user: user,
        tenant: tenant,
        actor: actor
      })

      {:ok, member}
    else
      %{} -> {:error, :already_member}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Leaves a tenant. The last owner cannot leave.
  """
  def leave_tenant(user, opts \\ []) when is_list(opts) do
    ensure!()

    with {:ok, tenant, member} <- member_tenant(user, opts),
         :ok <- authorize_leave(member) do
      Repo.delete!(member)
      clear_active_tenant(user.id, tenant.id)
      {:ok, member}
    end
  end

  @doc """
  Whether `member_or_roles` grants `action` on `resource`.

  Resources are `:tenant`, `:member`, and `:invitation`.
  """
  def permit?(member_or_roles, resource, action) do
    Access.permit?(member_or_roles, resource, action)
  end

  defp insert_tenant(user, attrs, role, opts) do
    changeset = tenant_changeset(struct(tenant_schema()), attrs, opts)

    with :ok <- changeset_ok(changeset),
         :ok <- under_membership_limit(changeset.data, user, opts) do
      member_cs =
        member_schema()
        |> struct()
        |> change(user_id: user.id, role: role)
        |> validate_required([:user_id, :role])

      result =
        Multi.new()
        |> Multi.insert(:tenant, changeset)
        |> Multi.insert(:member, fn %{tenant: tenant} ->
          put_change(member_cs, :tenant_id, tenant.id)
        end)
        |> Repo.transaction()

      case result do
        {:ok, inserted} -> {:ok, inserted}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  defp save_tenant(tenant, attrs, opts) do
    changeset = tenant_changeset(tenant, attrs, opts)

    case Repo.update(changeset) do
      {:ok, tenant} -> {:ok, tenant}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp tenant_changeset(tenant, attrs, opts) do
    attrs = stringify_keys(attrs)

    tenant
    |> cast(attrs, [:name, :slug, :logo, :metadata])
    |> update_change(:slug, &normalize_slug/1)
    |> validate_required([:name, :slug])
    |> validate_length(:name, max: 255)
    |> validate_format(:slug, @slug, message: "must be lowercase letters, numbers, and hyphens")
    |> unique_slug()
    |> host_changeset(attrs, opts)
  end

  defp unique_slug(changeset) do
    changeset =
      if get_change(changeset, :slug) do
        unsafe_validate_unique(changeset, :slug, Repo.repo())
      else
        changeset
      end

    unique_constraint(changeset, :slug)
  end

  defp host_changeset(changeset, attrs, opts) do
    case Keyword.get(opts, :changeset) do
      nil -> changeset
      fun when is_function(fun, 2) -> fun.(changeset, attrs)
    end
  end

  defp delete_tenant_rows(tenant) do
    multi =
      Multi.new()
      |> maybe_clear_all_sessions(tenant)
      |> Multi.delete_all(
        :invitations,
        from(i in invitation_schema(), where: i.tenant_id == ^tenant.id)
      )
      |> Multi.delete_all(:members, from(m in member_schema(), where: m.tenant_id == ^tenant.id))
      |> Multi.delete(:tenant, tenant)

    case Repo.transaction(multi) do
      {:ok, result} -> {:ok, result}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  defp maybe_clear_all_sessions(multi, tenant) do
    if active_tenant_field?() do
      query = from(t in user_token_schema(), where: t.active_tenant_id == ^tenant.id)
      Multi.update_all(multi, :sessions, query, set: [active_tenant_id: nil])
    else
      multi
    end
  end

  defp write_active_tenant(session, nil) do
    Repo.update(change(session, active_tenant_id: nil))
  end

  defp write_active_tenant(session, ref) do
    with {:ok, tenant} <- fetch_tenant_ref(ref),
         {:ok, _member} <- fetch_member_in(session.user_id, tenant.id) do
      Repo.update(change(session, active_tenant_id: tenant.id))
    end
  end

  defp deliver_invitation(tenant, inviter, email, role, send, attrs, opts) do
    pending = pending_for_email(tenant, email)
    resend? = truthy?(attr(attrs, :resend)) or truthy?(opt(opts, :resend, false))
    cancel? = truthy?(opt(opts, :cancel_pending_on_reinvite, false))

    cond do
      pending != [] and not resend? and not cancel? ->
        {:error, :already_invited}

      pending != [] and resend? and not cancel? ->
        rotate_invitation(hd(pending), tenant, inviter, role, send, opts)

      true ->
        create_invitation(tenant, inviter, email, role, send, pending, cancel?, opts)
    end
  end

  defp rotate_invitation(invitation, tenant, inviter, role, send, opts) do
    {encoded, hash, expires_at} = invitation_secret(opts)

    payload = %{
      invitation: %{email: invitation.email, role: role, expires_at: expires_at},
      inviter: inviter,
      tenant: tenant
    }

    with {:ok, payload} <- before_hook(opts, :before_create_invitation, payload),
         {:ok, role} <- normalize_roles(payload.invitation.role),
         {:ok, invitation} <-
           transact(fn ->
             case Repo.update(
                    change(invitation,
                      token: hash,
                      role: role,
                      expires_at: expires_at,
                      status: :pending
                    )
                  ) do
               {:ok, invitation} -> deliver!(send, invitation, encoded)
               {:error, changeset} -> rollback(changeset)
             end
           end) do
      after_hook(opts, :after_create_invitation, %{
        invitation: invitation,
        inviter: inviter,
        tenant: tenant
      })

      {:ok, public_invitation(invitation)}
    end
  end

  defp create_invitation(tenant, inviter, email, role, send, pending, cancel?, opts) do
    {encoded, hash, expires_at} = invitation_secret(opts)

    payload = %{
      invitation: %{email: email, role: role, expires_at: expires_at},
      inviter: inviter,
      tenant: tenant
    }

    with {:ok, payload} <- before_hook(opts, :before_create_invitation, payload),
         {:ok, role} <- normalize_roles(payload.invitation.role),
         :ok <- within_invitation_limit(tenant, length(pending), cancel?, opts),
         {:ok, invitation} <-
           insert_invitation(
             tenant,
             inviter,
             payload.invitation.email,
             role,
             hash,
             expires_at,
             pending,
             cancel?,
             send,
             encoded
           ) do
      after_hook(opts, :after_create_invitation, %{
        invitation: invitation,
        inviter: inviter,
        tenant: tenant
      })

      {:ok, public_invitation(invitation)}
    end
  end

  defp insert_invitation(
         tenant,
         inviter,
         email,
         role,
         hash,
         expires_at,
         pending,
         cancel?,
         send,
         encoded
       ) do
    changeset =
      invitation_schema()
      |> struct()
      |> change(
        tenant_id: tenant.id,
        inviter_id: inviter.id,
        email: email,
        role: role,
        token: hash,
        expires_at: expires_at,
        status: :pending
      )
      |> validate_required([:tenant_id, :inviter_id, :email, :role, :token, :expires_at])

    transact(fn ->
      if cancel? do
        Enum.each(pending, fn invitation ->
          Repo.update!(change(invitation, status: :canceled))
        end)
      end

      case Repo.insert(changeset) do
        {:ok, invitation} -> deliver!(send, invitation, encoded)
        {:error, changeset} -> rollback(changeset)
      end
    end)
  end

  defp transact(fun), do: Repo.transaction(fun)

  defp rollback(reason), do: Repo.repo().rollback(reason)

  defp deliver!(send, invitation, encoded) do
    case send.(public_invitation(invitation), encoded) do
      {:error, reason} -> rollback(reason)
      _ -> invitation
    end
  end

  defp accept_rows(invitation, user, tenant) do
    member_cs =
      member_schema()
      |> struct()
      |> change(tenant_id: tenant.id, user_id: user.id, role: invitation.role)
      |> validate_required([:tenant_id, :user_id, :role])
      |> unique_constraint([:tenant_id, :user_id])

    result =
      Multi.new()
      |> Multi.update(:invitation, change(invitation, status: :accepted))
      |> Multi.insert(:member, member_cs)
      |> Repo.transaction()

    case result do
      {:ok, inserted} -> {:ok, inserted}
      {:error, :member, %Ecto.Changeset{}, _} -> {:error, :already_member}
      {:error, _step, reason, _} -> {:error, reason}
    end
  end

  defp invitation_for_user(user, raw_token) do
    with {:ok, invitation} <- fetch_invitation_token(raw_token),
         :ok <- pending_only(invitation),
         :ok <- unexpired(invitation),
         :ok <- email_matches(user, invitation),
         :ok <- email_confirmed(user) do
      if Repo.get_by(member_schema(), tenant_id: invitation.tenant_id, user_id: user.id) do
        {:error, :already_member}
      else
        {:ok, invitation}
      end
    end
  end

  defp fetch_invitation_token(raw_token) do
    case hash_token(raw_token) do
      {:ok, hash} ->
        case Repo.get_by(invitation_schema(), token: hash) do
          nil -> {:error, :invalid_invitation}
          invitation -> {:ok, invitation}
        end

      :error ->
        {:error, :invalid_invitation}
    end
  end

  defp invitation_secret(opts) do
    raw = :crypto.strong_rand_bytes(32)
    hash = :crypto.hash(:sha256, raw)
    encoded = Base.url_encode64(raw, padding: false)
    hours = opt(opts, :invitation_expires_in, 48)
    expires_at = DateTime.add(DateTime.utc_now(), hours, :hour)
    {encoded, hash, expires_at}
  end

  defp hash_token(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, raw} -> {:ok, :crypto.hash(:sha256, raw)}
      :error -> :error
    end
  end

  defp insert_member(tenant, user, role) do
    member_schema()
    |> struct()
    |> change(tenant_id: tenant.id, user_id: user.id, role: role)
    |> validate_required([:tenant_id, :user_id, :role])
    |> unique_constraint([:tenant_id, :user_id])
    |> Repo.insert()
    |> case do
      {:ok, member} -> {:ok, member}
      {:error, %Ecto.Changeset{}} -> {:error, :already_member}
    end
  end

  defp save_role(member, roles) do
    case Repo.update(change(member, role: roles)) do
      {:ok, member} -> {:ok, member}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp set_status(invitation, status) do
    case Repo.update(change(invitation, status: status)) do
      {:ok, invitation} -> {:ok, invitation}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp member_tenant(user, opts) do
    with {:ok, tenant} <- tenant_from_opts(user, opts),
         {:ok, member} <- fetch_member(user, tenant) do
      {:ok, tenant, member}
    end
  end

  defp tenant_from_opts(user, opts) do
    cond do
      id = opt_value(opts, :tenant_id) -> fetch_tenant_by_id(id)
      slug = opt_value(opts, :slug) -> fetch_tenant_by_slug(slug)
      session = opt_value(opts, :session) -> tenant_from_session(user, session)
      true -> {:error, :tenant_required}
    end
  end

  defp tenant_from_session(user, token) do
    ensure_active_tenant_field!()

    with {:ok, session} <- load_session(token) do
      cond do
        session.user_id != user.id -> {:error, :invalid_session}
        is_nil(session.active_tenant_id) -> {:error, :no_active_tenant}
        true -> fetch_tenant_by_id(session.active_tenant_id)
      end
    end
  end

  defp load_session(token) when is_binary(token) do
    case Repo.one(session_query(token)) do
      nil -> load_decoded_session(token)
      session -> {:ok, session}
    end
  end

  defp load_session(%{token: token} = session) when is_binary(token) do
    if active_tenant_field?() and Map.has_key?(session, :id) and not is_nil(session.id) do
      {:ok, session}
    else
      load_session(token)
    end
  end

  defp load_session(_), do: {:error, :invalid_session}

  defp load_decoded_session(token) do
    case AuthKit.UserToken.decode_session_token(token) do
      {:ok, raw} when raw != token ->
        case Repo.one(session_query(raw)) do
          nil -> {:error, :invalid_session}
          session -> {:ok, session}
        end

      _ ->
        {:error, :invalid_session}
    end
  end

  defp session_query(token) do
    now = DateTime.utc_now()

    from(t in user_token_schema(),
      where: t.token == ^token and t.context == "session" and t.expires_at > ^now
    )
  end

  defp fetch_tenant_ref(%_{} = tenant) do
    if is_struct(tenant, tenant_schema()), do: {:ok, tenant}, else: {:error, :not_found}
  end

  defp fetch_tenant_ref(%{id: id}) when not is_nil(id), do: fetch_tenant_by_id(id)
  defp fetch_tenant_ref(%{"id" => id}) when not is_nil(id), do: fetch_tenant_by_id(id)
  defp fetch_tenant_ref(%{slug: slug}) when is_binary(slug), do: fetch_tenant_by_slug(slug)
  defp fetch_tenant_ref(%{"slug" => slug}) when is_binary(slug), do: fetch_tenant_by_slug(slug)

  defp fetch_tenant_ref(ref) when is_binary(ref) do
    case fetch_tenant_by_id(ref) do
      {:ok, tenant} -> {:ok, tenant}
      {:error, :not_found} -> fetch_tenant_by_slug(ref)
    end
  end

  defp fetch_tenant_ref(ref) when is_integer(ref), do: fetch_tenant_by_id(ref)
  defp fetch_tenant_ref(_ref), do: {:error, :not_found}

  defp fetch_tenant_by_id(id) do
    case Repo.get(tenant_schema(), id) do
      nil -> {:error, :not_found}
      tenant -> {:ok, tenant}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  defp fetch_tenant_by_slug(slug) when is_binary(slug) do
    case Repo.get_by(tenant_schema(), slug: normalize_slug(slug)) do
      nil -> {:error, :not_found}
      tenant -> {:ok, tenant}
    end
  end

  defp as_tenant(tenant) do
    if is_struct(tenant, tenant_schema()), do: {:ok, tenant}, else: fetch_tenant_by_id(tenant)
  end

  defp fetch_member(user, tenant) do
    fetch_member_in(user.id, tenant.id)
  end

  defp fetch_member_in(user_id, tenant_id) do
    case Repo.get_by(member_schema(), user_id: user_id, tenant_id: tenant_id) do
      nil -> {:error, :not_member}
      member -> {:ok, member}
    end
  end

  defp fetch_member_by_id(id) do
    case Repo.get(member_schema(), id) do
      nil -> {:error, :not_found}
      member -> {:ok, member}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  defp fetch_invitation(id) do
    case Repo.get(invitation_schema(), id) do
      nil -> {:error, :not_found}
      invitation -> {:ok, invitation}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  defp fetch_user(nil), do: {:error, :not_found}

  defp fetch_user(id) do
    case Repo.get(user_schema(), id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  rescue
    Ecto.Query.CastError -> {:error, :not_found}
  end

  defp authorize_add(:system, _tenant, _attrs), do: :ok

  defp authorize_add(actor, tenant, attrs) do
    with {:ok, member} <- fetch_member(actor, tenant),
         :ok <- permit(member, :member, :create),
         {:ok, role} <- normalize_roles(attr(attrs, :role) || ["member"]) do
      authorize_owner_grant(member, role)
    end
  end

  defp authorize_owner_grant(member, roles) do
    if "owner" in roles and "owner" not in member.role do
      {:error, :forbidden}
    else
      :ok
    end
  end

  defp authorize_owner_change(actor, target, new_roles) do
    was = "owner" in target.role
    now = "owner" in new_roles

    cond do
      was == now -> :ok
      "owner" not in actor.role -> {:error, :forbidden}
      was and not now and last_owner?(target) -> {:error, :last_owner}
      true -> :ok
    end
  end

  defp authorize_remove(actor, target) do
    cond do
      "owner" in target.role and "owner" not in actor.role -> {:error, :forbidden}
      "owner" in target.role and last_owner?(target) -> {:error, :last_owner}
      true -> :ok
    end
  end

  defp authorize_leave(member) do
    if "owner" in member.role and last_owner?(member) do
      {:error, :last_owner}
    else
      :ok
    end
  end

  defp last_owner?(member) do
    owner_ids(member.tenant_id) == [member.id]
  end

  defp owner_ids(tenant_id) do
    from(m in member_schema(),
      where: m.tenant_id == ^tenant_id,
      select: {m.id, m.role}
    )
    |> Repo.all()
    |> Enum.filter(fn {_id, roles} -> is_list(roles) and "owner" in roles end)
    |> Enum.map(&elem(&1, 0))
  end

  defp not_already_member(tenant, email) do
    exists =
      Repo.exists?(
        from(m in member_schema(),
          join: u in assoc(m, :user),
          where: m.tenant_id == ^tenant.id and fragment("lower(?)", u.email) == ^email
        )
      )

    if exists, do: {:error, :already_member}, else: :ok
  end

  defp pending_for_email(tenant, email) do
    from(i in invitation_schema(),
      where: i.tenant_id == ^tenant.id and i.email == ^email and i.status == :pending,
      order_by: [asc: i.email]
    )
    |> Repo.all()
  end

  defp pending_invitations(tenant) do
    from(i in invitation_schema(),
      where: i.tenant_id == ^tenant.id and i.status == :pending,
      order_by: [asc: i.email]
    )
    |> Repo.all()
  end

  defp pending_only(%{status: :pending}), do: :ok
  defp pending_only(_invitation), do: {:error, :invalid_invitation}

  defp unexpired(%{expires_at: expires_at}) do
    if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
      :ok
    else
      {:error, :expired}
    end
  end

  defp email_matches(user, invitation) do
    if String.downcase(user.email || "") == String.downcase(invitation.email) do
      :ok
    else
      {:error, :email_mismatch}
    end
  end

  defp email_confirmed(%{email_confirmed_at: nil}), do: {:error, :email_not_confirmed}
  defp email_confirmed(_user), do: :ok

  defp allow_create(user, opts) do
    allowed =
      case opt(opts, :allow_create, true) do
        true -> true
        false -> false
        fun when is_function(fun, 1) -> fun.(user) == true
        _ -> false
      end

    if allowed, do: :ok, else: {:error, :create_forbidden}
  end

  defp within_tenant_limit(user, opts) do
    limit =
      case opt(opts, :tenant_limit, :unlimited) do
        :unlimited -> :unlimited
        fun when is_function(fun, 1) -> fun.(user)
        limit -> limit
      end

    count =
      Repo.one(from(m in member_schema(), where: m.user_id == ^user.id, select: count(m.id))) || 0

    if limit == :unlimited or (is_integer(limit) and count < limit) do
      :ok
    else
      {:error, :tenant_limit}
    end
  end

  defp under_membership_limit(tenant, user, opts) do
    limit = membership_limit(user, tenant, opts)
    count = member_count(tenant)

    if is_integer(limit) and count < limit do
      :ok
    else
      {:error, :membership_limit}
    end
  end

  defp membership_limit(user, tenant, opts) do
    case opt(opts, :membership_limit, 100) do
      fun when is_function(fun, 2) -> fun.(user, tenant)
      fun when is_function(fun, 1) -> fun.(user)
      limit -> limit
    end
  end

  defp members_limit(user, tenant, opts) do
    case Keyword.get(opts, :members_limit) do
      nil -> membership_limit(user, tenant, opts)
      fun when is_function(fun, 2) -> fun.(user, tenant)
      limit -> limit
    end
  end

  defp member_count(tenant) do
    id = Map.get(tenant, :id)

    if is_nil(id) do
      0
    else
      Repo.one(from(m in member_schema(), where: m.tenant_id == ^id, select: count(m.id))) || 0
    end
  end

  defp within_invitation_limit(tenant, pending_for_email, cancel?, opts) do
    limit = opt(opts, :invitation_limit, 100)
    count = pending_count(tenant)
    count = if cancel?, do: count - pending_for_email, else: count

    if is_integer(limit) and count < limit do
      :ok
    else
      {:error, :invitation_limit}
    end
  end

  defp pending_count(tenant) do
    Repo.one(
      from(i in invitation_schema(),
        where: i.tenant_id == ^tenant.id and i.status == :pending,
        select: count(i.id)
      )
    ) || 0
  end

  defp creator_role(opts) do
    case opt(opts, :creator_role, "owner") do
      role when role in ["owner", "admin"] -> {:ok, [role]}
      _ -> {:error, :invalid_creator_role}
    end
  end

  defp normalize_roles(roles) when is_binary(roles), do: normalize_roles([roles])

  defp normalize_roles(roles) when is_list(roles) and roles != [] do
    roles = Enum.map(roles, &to_string/1)

    if Enum.all?(roles, &role_ok?/1) and roles == Enum.uniq(roles) do
      {:ok, roles}
    else
      {:error, :invalid_role}
    end
  end

  defp normalize_roles(_roles), do: {:error, :invalid_role}

  defp role_ok?(role), do: role =~ ~r/^[a-z][a-z0-9_]*$/

  defp normalize_email(email) when is_binary(email) do
    email = email |> String.trim() |> String.downcase()

    if email =~ @email and String.length(email) <= 160 do
      {:ok, email}
    else
      {:error, :invalid_email}
    end
  end

  defp normalize_email(_email), do: {:error, :invalid_email}

  defp normalize_slug(nil), do: nil
  defp normalize_slug(slug) when is_binary(slug), do: slug |> String.trim() |> String.downcase()
  defp normalize_slug(slug), do: slug

  defp slug_ok?(slug) when is_binary(slug), do: slug =~ @slug
  defp slug_ok?(_slug), do: false

  defp slug_taken?(slug) do
    Repo.exists?(from(t in tenant_schema(), where: t.slug == ^slug))
  end

  defp clear_active_tenant(user_id, tenant_id) do
    if active_tenant_field?() do
      from(t in user_token_schema(),
        where: t.user_id == ^user_id and t.active_tenant_id == ^tenant_id
      )
      |> Repo.update_all(set: [active_tenant_id: nil])
    end

    :ok
  end

  defp public_invitation(invitation), do: %{invitation | token: nil}

  defp require_sender(fun) when is_function(fun, 2), do: :ok
  defp require_sender(_fun), do: {:error, :send_invitation_required}

  defp send_invitation(attrs, opts) do
    attr(attrs, :send_invitation) || opt(opts, :send_invitation, nil)
  end

  defp active_id(%{active_tenant_id: nil}), do: {:error, :no_active_tenant}
  defp active_id(%{active_tenant_id: id}), do: {:ok, id}

  defp changeset_ok(%Ecto.Changeset{valid?: true}), do: :ok
  defp changeset_ok(changeset), do: {:error, changeset}

  defp before_ok(opts, name, payload) do
    case before_hook(opts, name, payload) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp before_hook(opts, name, payload) do
    case hook(opts, name) do
      nil ->
        {:ok, payload}

      fun ->
        case fun.(payload) do
          :ok -> {:ok, payload}
          {:ok, %{} = updates} -> {:ok, merge_payload(payload, updates)}
          {:error, reason} -> {:error, reason}
          _ -> {:error, :invalid_hook}
        end
    end
  end

  defp after_hook(opts, name, payload) do
    case hook(opts, name) do
      nil -> :ok
      fun -> fun.(payload)
    end

    :ok
  end

  defp merge_payload(payload, updates) do
    Map.merge(payload, updates, fn
      :attrs, old, new when is_map(old) and is_map(new) ->
        Map.merge(stringify_keys(old), stringify_keys(new))

      :member, old, new when is_map(old) and is_map(new) ->
        Map.merge(old, new)

      :invitation, old, new when is_map(old) and is_map(new) ->
        Map.merge(old, new)

      _key, _old, new ->
        new
    end)
  end

  defp hook(opts, name) do
    configured = Application.get_env(:auth_kit, :tenant_hooks, %{})

    configured
    |> Map.merge(hook_map(opts))
    |> Map.get(name)
  end

  defp hook_map(opts) when is_list(opts) do
    case Keyword.get(opts, :hooks, %{}) do
      hooks when is_map(hooks) -> hooks
      hooks when is_list(hooks) -> Map.new(hooks)
    end
  end

  defp hook_map(attrs) when is_map(attrs) do
    case attr(attrs, :hooks) do
      hooks when is_map(hooks) -> hooks
      _ -> %{}
    end
  end

  defp opt(opts, key, default) do
    if Keyword.has_key?(opts, key) do
      opts[key]
    else
      :auth_kit
      |> Application.get_env(:tenant_options, [])
      |> Keyword.get(key, default)
    end
  end

  defp opt_value(opts, key) do
    if Keyword.has_key?(opts, key), do: opts[key]
  end

  defp attr(attrs, key) do
    Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))
  end

  defp stringify_keys(attrs) when is_map(attrs) do
    Map.new(attrs, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  defp truthy?(value), do: value in [true, "true", 1]

  defp permit(member, resource, action) do
    if Access.permit?(member, resource, action), do: :ok, else: {:error, :forbidden}
  end

  defp ensure! do
    AuthKit.Config.tenant_schema()
    AuthKit.Config.tenant_member_schema()
    AuthKit.Config.tenant_invitation_schema()
    :ok
  end

  defp ensure_active_tenant_field! do
    if active_tenant_field?() do
      :ok
    else
      raise ArgumentError, """
      The user token schema needs auth_kit_active_tenant_field/0 so a session can store the active tenant.
      """
    end
  end

  defp active_tenant_field? do
    :active_tenant_id in user_token_schema().__schema__(:fields)
  end

  defp tenant_schema, do: AuthKit.Config.tenant_schema()
  defp member_schema, do: AuthKit.Config.tenant_member_schema()
  defp invitation_schema, do: AuthKit.Config.tenant_invitation_schema()
  defp user_schema, do: AuthKit.Config.user_schema()
  defp user_token_schema, do: AuthKit.Config.user_token_schema()
end
