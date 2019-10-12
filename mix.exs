defmodule NoWayJose.MixProject do
  use Mix.Project

  def project do
    [
      app: :no_way_jose,
      compilers: [:rustler] ++ Mix.compilers(),
      deps: deps(),
      elixir: "~> 1.8",
      rustler_crates: [nowayjose: []],
      start_permanent: Mix.env() == :prod,
      version: "0.1.0"
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {NoWayJose.Application, []}
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.21"},

      # Test deps
      {:jason, "~> 1.0", only: [:dev, :test]}
    ]
  end
end
