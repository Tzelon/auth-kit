defmodule AuthKit.Test.Repo.Migrations.CreateAuthTables do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:email, :string)
      add(:name, :string)
      add(:phone_number, :string)
      add(:phone_verified_at, :utc_datetime)
      add(:avatar_url, :string)
      add(:email_confirmed_at, :utc_datetime)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:users, [:email]))
    create(unique_index(:users, [:phone_number]))

    create table(:identities, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:identity, :string)
      add(:provider, :string)
      add(:access_token, :text)
      add(:refresh_token, :text)
      add(:access_token_expires_at, :utc_datetime_usec)
      add(:refresh_token_expires_at, :utc_datetime_usec)
      add(:scope, :string)
      add(:id_token, :text)
      add(:password, :string)
      add(:state, :string, default: "active")
      add(:provider_meta, :map, default: %{})
      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false)

      timestamps()
    end

    create(index(:identities, [:user_id, :provider]))

    create table(:users_tokens, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:token, :binary, null: false)
      add(:context, :string, null: false)
      add(:sent_to, :string)
      add(:confirmed_at, :utc_datetime_usec)
      add(:expires_at, :utc_datetime_usec)
      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all))

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(index(:users_tokens, [:user_id]))
    create(unique_index(:users_tokens, [:context, :token]))
  end
end
