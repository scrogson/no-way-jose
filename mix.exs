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
      name: "NoWayJose",
      package: [
        exclude_patterns: [
          ~r/\W\.DS_Store$/,
          ~r/target/
        ],
        files: ["lib", "native", "mix.exs", "README.md", "LICENSE"],
        licenses: ["Apache-2.0"],
        links: %{"GitHub" => "https://github.com/scrogson/no-way-jose"},
        maintainers: ["Sonny Scroggin"]
      ],
      rustler_crates: [
        nowayjose: []
      ],
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
end
