defmodule AuthKit.TenantsTest do
  use AuthKit.DataCase, async: true

  alias AuthKit.Auth
  alias AuthKit.Tenants
  alias AuthKit.Test.Tenant
  alias AuthKit.Test.TenantInvitation
  alias AuthKit.Test.UserToken

  test "create assigns the creator as the only owner and rejects a duplicate slug" do
    user = confirmed_user()

    assert {:ok, :available} = Tenants.check_slug("Acme")

    assert {:ok, %{tenant: tenant, member: member}} =
             Tenants.create_tenant(user, %{name: "Acme", slug: "Acme"})

    assert tenant.slug == "acme"
    assert member.user_id == user.id
    assert member.role == ["owner"]
    assert {:ok, [listed]} = Tenants.list_tenants(user)
    assert listed.id == tenant.id
    assert {:ok, [listed_member]} = Tenants.list_members(user, tenant_id: tenant.id)
    assert listed_member.id == member.id

    assert {:error, :taken} = Tenants.check_slug("acme")

    assert {:error, changeset} =
             Tenants.create_tenant(confirmed_user(), %{name: "Other", slug: "acme"})

    assert Keyword.has_key?(changeset.errors, :slug)
  end

  test "a member cannot update or delete, an admin cannot delete, and an owner can" do
    owner = confirmed_user()
    admin = confirmed_user()
    member = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})

    assert {:ok, _} = Tenants.add_member(owner, tenant, %{user_id: admin.id, role: ["admin"]})
    assert {:ok, _} = Tenants.add_member(owner, tenant, %{user_id: member.id, role: ["member"]})

    assert {:error, :forbidden} =
             Tenants.update_tenant(member, %{name: "Nope"}, tenant_id: tenant.id)

    assert {:error, :forbidden} = Tenants.delete_tenant(member, tenant_id: tenant.id)

    assert {:ok, updated} = Tenants.update_tenant(admin, %{name: "Acme 2"}, tenant_id: tenant.id)
    assert updated.name == "Acme 2"
    assert {:error, :forbidden} = Tenants.delete_tenant(admin, tenant_id: tenant.id)

    assert {:ok, _} = Tenants.delete_tenant(owner, tenant_id: tenant.id)
    assert {:error, :not_found} = Tenants.get_tenant(owner, tenant_id: tenant.id)
  end

  test "the last owner cannot leave, be removed, or be demoted" do
    owner = confirmed_user()
    other = confirmed_user()
    admin = confirmed_user()

    {:ok, %{tenant: tenant, member: owner_member}} =
      Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})

    {:ok, admin_member} = Tenants.add_member(owner, tenant, %{user_id: admin.id, role: ["admin"]})

    assert {:error, :last_owner} = Tenants.leave_tenant(owner, tenant_id: tenant.id)
    assert {:error, :last_owner} = Tenants.remove_member(owner, owner_member.id)
    assert {:error, :last_owner} = Tenants.update_member_role(owner, owner_member.id, ["admin"])
    assert {:error, :forbidden} = Tenants.remove_member(admin, owner_member.id)
    assert {:error, :forbidden} = Tenants.update_member_role(admin, owner_member.id, ["member"])

    assert {:ok, _} =
             Tenants.add_member(:system, tenant, %{user_id: other.id, role: ["owner"]})

    assert {:ok, demoted} = Tenants.update_member_role(other, owner_member.id, ["admin"])
    assert demoted.role == ["admin"]
    assert {:ok, _} = Tenants.leave_tenant(admin, tenant_id: tenant.id)
    refute Repo.get(AuthKit.Test.TenantMember, admin_member.id)
  end

  test "invitations can be sent, resent, accepted, rejected, canceled, and they expire" do
    owner = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})
    sender = fn invitation, token -> send(self(), {:token, invitation.email, token}) end

    assert {:ok, invitation} =
             Tenants.invite(tenant, owner, %{
               email: "Ada@example.com",
               role: ["member"],
               send_invitation: sender
             })

    assert invitation.email == "ada@example.com"
    assert invitation.token == nil
    assert_received {:token, "ada@example.com", first_token}

    assert {:error, :already_invited} =
             Tenants.invite(tenant, owner, %{
               email: "ada@example.com",
               role: ["member"],
               send_invitation: sender
             })

    assert {:ok, _} =
             Tenants.invite(tenant, owner, %{
               email: "ada@example.com",
               role: ["admin"],
               resend: true,
               send_invitation: sender
             })

    assert_received {:token, "ada@example.com", second_token}
    refute first_token == second_token

    guest = user_with_email("ada@example.com")
    assert {:error, :email_not_confirmed} = Tenants.accept_invitation(guest, second_token)
    assert {:error, :invalid_invitation} = Tenants.accept_invitation(guest, first_token)

    {:ok, guest, _} = Auth.confirm_user_email(guest)
    assert {:ok, %{member: member}} = Tenants.accept_invitation(guest, second_token)
    assert member.role == ["admin"]
    assert {:error, :invalid_invitation} = Tenants.accept_invitation(guest, second_token)

    assert {:error, :already_member} =
             Tenants.invite(tenant, owner, %{
               email: "ada@example.com",
               role: ["member"],
               send_invitation: sender
             })

    assert {:ok, rejected} =
             Tenants.invite(tenant, owner, %{
               email: "bea@example.com",
               role: ["member"],
               send_invitation: sender
             })

    assert_received {:token, "bea@example.com", reject_token}
    bea = confirmed_user(%{email: "bea@example.com"})
    assert {:ok, invitation} = Tenants.get_invitation(bea, reject_token)
    assert invitation.id == rejected.id
    assert {:ok, %{status: :rejected}} = Tenants.reject_invitation(bea, reject_token)

    assert {:ok, _} =
             Tenants.invite(tenant, owner, %{
               email: "cy@example.com",
               role: ["member"],
               send_invitation: sender
             })

    cy = confirmed_user(%{email: "cy@example.com"})
    assert {:ok, [pending | _]} = Tenants.list_user_invitations(cy)
    assert pending.email == "cy@example.com"
    assert {:ok, _} = Tenants.cancel_invitation(owner, pending.id)
    assert {:ok, []} = Tenants.list_user_invitations(cy)

    assert {:ok, _} =
             Tenants.invite(tenant, owner, %{
               email: "dee@example.com",
               role: ["member"],
               send_invitation: sender
             })

    assert_received {:token, "dee@example.com", expired_token}
    expired = Repo.get_by!(TenantInvitation, email: "dee@example.com")

    expired
    |> Ecto.Changeset.change(expires_at: DateTime.add(DateTime.utc_now(), -60, :second))
    |> Repo.update!()

    dee = confirmed_user(%{email: "dee@example.com"})
    assert {:error, :expired} = Tenants.accept_invitation(dee, expired_token)
  end

  test "accepting a token for a different email fails" do
    owner = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})

    Tenants.invite(tenant, owner, %{
      email: "ada@example.com",
      role: ["member"],
      send_invitation: fn _invitation, token -> send(self(), {:token, token}) end
    })

    assert_received {:token, token}
    other = confirmed_user()
    assert {:error, :email_mismatch} = Tenants.accept_invitation(other, token)
  end

  test "reinvite can cancel the previous pending invitation" do
    owner = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})
    sender = fn _invitation, token -> send(self(), {:token, token}) end

    Tenants.invite(tenant, owner, %{
      email: "ada@example.com",
      role: ["member"],
      send_invitation: sender
    })

    assert {:ok, _} =
             Tenants.invite(
               tenant,
               owner,
               %{
                 email: "ada@example.com",
                 role: ["member"],
                 send_invitation: sender
               },
               cancel_pending_on_reinvite: true
             )

    assert {:ok, invitations} = Tenants.list_invitations(owner, slug: "acme")
    assert Enum.count(invitations, &(&1.status == :canceled)) == 1
    assert Enum.count(invitations, &(&1.status == :pending)) == 1
    assert Enum.all?(invitations, &is_nil(&1.token))
  end

  test "set_active_tenant rejects a tenant the user is not in, and delete clears it" do
    owner = confirmed_user()
    other = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})
    {:ok, %{tenant: other_tenant}} = Tenants.create_tenant(other, %{name: "Other", slug: "other"})

    token = Auth.generate_session_token(owner)
    other_token = Auth.generate_session_token(owner)

    assert {:error, :not_member} = Tenants.set_active_tenant(token, other_tenant.id)
    assert {:ok, session} = Tenants.set_active_tenant(token, tenant.slug)
    assert session.active_tenant_id == tenant.id

    {:ok, %{tenant: second}} = Tenants.create_tenant(owner, %{name: "Beta", slug: "beta"})
    assert {:ok, _} = Tenants.set_active_tenant(other_token, %{id: second.id})

    assert {:ok, member} = Tenants.active_member(token)
    assert member.role == ["owner"]
    assert {:ok, ["owner"]} = Tenants.active_member_role(token)
    assert {:ok, active} = Tenants.get_tenant(owner, session: other_token)
    assert active.id == second.id

    assert {:ok, _} = Tenants.set_active_tenant(token, nil)
    assert {:error, :no_active_tenant} = Tenants.active_member(token)

    assert {:ok, session} = Tenants.set_active_tenant(token, tenant.id)
    assert {:ok, _} = Tenants.delete_tenant(owner, tenant_id: tenant.id)
    assert Repo.get!(UserToken, session.id).active_tenant_id == nil
    assert Repo.all(TenantInvitation) |> Enum.all?(&(&1.tenant_id != tenant.id))
  end

  test "membership and invitation limits" do
    owner = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})
    sender = fn _invitation, _token -> :ok end

    assert {:ok, _} =
             Tenants.add_member(owner, tenant, %{user_id: confirmed_user().id},
               membership_limit: 2
             )

    assert {:error, :membership_limit} =
             Tenants.add_member(owner, tenant, %{user_id: confirmed_user().id},
               membership_limit: 2
             )

    assert {:ok, _} =
             Tenants.invite(
               tenant,
               owner,
               %{
                 email: "one@example.com",
                 role: ["member"],
                 send_invitation: sender
               },
               invitation_limit: 1
             )

    assert {:error, :invitation_limit} =
             Tenants.invite(
               tenant,
               owner,
               %{
                 email: "two@example.com",
                 role: ["member"],
                 send_invitation: sender
               },
               invitation_limit: 1
             )
  end

  test "a before hook error leaves the database unchanged" do
    user = confirmed_user()

    assert {:error, :halt} =
             Tenants.create_tenant(user, %{name: "Acme", slug: "acme"},
               hooks: %{before_create_tenant: fn _payload -> {:error, :halt} end}
             )

    assert Repo.aggregate(Tenant, :count) == 0
  end

  test "full tenant includes members and pending invitations without secrets" do
    owner = confirmed_user()
    {:ok, %{tenant: tenant}} = Tenants.create_tenant(owner, %{name: "Acme", slug: "acme"})

    Tenants.invite(tenant, owner, %{
      email: "ada@example.com",
      role: ["member"],
      send_invitation: fn _invitation, _token -> :ok end
    })

    assert {:ok, %{members: [member], invitations: [invitation]}} =
             Tenants.get_full_tenant(owner, slug: "acme")

    assert member.user_id == owner.id
    assert invitation.email == "ada@example.com"
    assert invitation.token == nil
  end

  defp confirmed_user(attrs \\ %{}) do
    user = AuthKit.Fixtures.user_fixture(attrs)
    {:ok, user, _} = Auth.confirm_user_email(user)
    user
  end

  defp user_with_email(email) do
    AuthKit.Fixtures.user_fixture(%{email: email})
  end
end
