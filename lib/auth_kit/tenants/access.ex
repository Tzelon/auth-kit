defmodule AuthKit.Tenants.Access do
  @moduledoc false

  @grants %{
    "owner" => %{
      tenant: [:update, :delete],
      member: [:create, :update, :delete],
      invitation: [:create, :cancel]
    },
    "admin" => %{
      tenant: [:update],
      member: [:create, :update, :delete],
      invitation: [:create, :cancel]
    },
    "member" => %{
      tenant: [],
      member: [],
      invitation: []
    }
  }

  @doc """
  Whether any of the member's roles grants `action` on `resource`.

  `member_or_roles` is a member struct or a list of role names.
  """
  def permit?(member, resource, action) when is_struct(member) do
    permit?(Map.get(member, :role), resource, action)
  end

  def permit?(roles, resource, action)
      when is_list(roles) and is_atom(resource) and is_atom(action) do
    Enum.any?(roles, fn role ->
      role
      |> grants()
      |> Map.get(resource, [])
      |> Enum.member?(action)
    end)
  end

  def permit?(_, _, _), do: false

  defp grants(role) when is_binary(role), do: Map.get(@grants, role, %{})
  defp grants(_role), do: %{}
end
