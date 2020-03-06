defmodule NoWayJose.MixProject do
  use Mix.Project

  @description """
  Rust NIF for signing JWTs
  """

  @version "0.1.0"

  def project do
    [
      app: :no_way_jose,
      compilers: [:rustler] ++ Mix.compilers(),
      deps: deps(),
      description: @description,
      docs: [
        main: "readme",
        extras: ["README.md"],
        source_url_pattern:
          "https://github.com/scrogson/no-way-jose/blob/v#{@version}/%{path}#L%{line}"
      ],
      elixir: "~> 1.8",
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "NoWayJose",
      package: [
        files: ["lib", "native", "mix.exs", "README.md", "LICENSE"],
        licenses: ["Apache-2.0"],
        links: %{"GitHub" => "https://github.com/scrogson/no-way-jose"},
        maintainers: ["Sonny Scroggin"]
      ],
      rustler_crates: rustler_crates(Mix.env()),
      start_permanent: Mix.env() == :prod,
      version: @version
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

      # dev & test deps
      {:ex_doc, "~> 0.21", only: :dev},
      {:jason, "~> 1.0", only: [:dev, :test]}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp rustler_crates(:test) do
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
