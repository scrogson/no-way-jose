defmodule NoWayJose.MixProject do
  use Mix.Project

  def project do
    [
      app: :no_way_jose,
      compilers: [:rustler] ++ Mix.compilers(),
      deps: deps(),
      elixir: "~> 1.8",
      elixirc_paths: elixirc_paths(Mix.env()),
      rustler_crates: rustler_crates(Mix.env()),
      start_permanent: Mix.env() == :prod,
      version: "0.1.0"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.21"},

      # Test deps
      {:jason, "~> 1.0", only: [:dev, :test]}
    ]
  end

  defp elixirc_paths(env) when env in [:dev, :test], do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp rustler_crates(env) when env in [:dev, :test] do
    [
      nowayjose: [],
      nowayjose_testutils: []
    ]
  end

  defp rustler_crates(_) do
    [
      nowayjose: []
    ]
  end
end
