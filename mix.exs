defmodule AuthKit.MixProject do
  use Mix.Project

  def project do
    [
      app: :auth_kit,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      source_url: "https://github.com/Tzelon/auth-kit"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :ssl, :inets]
    ]
  end

  # Dependencies compile in :prod, so the test schemas never reach host apps.
  defp elixirc_paths(:prod), do: ["lib"]
  defp elixirc_paths(_env), do: ["lib", "test/support"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.14"},
      {:ecto, "~> 3.10"},
      {:ecto_ksuid, "~> 0.3.0"}
    ]
  end
end
