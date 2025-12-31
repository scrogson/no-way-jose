defmodule NoWayJose.MixProject do
  use Mix.Project

  @description "Rust NIF for signing and verifying JWTs with JWKS support"
  @source_url "https://github.com/scrogson/no-way-jose"
  @version "1.0.1"

  def project do
    [
      app: :no_way_jose,
      deps: [
        {:jason, "~> 1.0"},
        {:rustler, "~> 0.37", optional: true},
        {:rustler_precompiled, "~> 0.8"},
        {:telemetry, "~> 1.0"},

        # Optional HTTP client for JWKS fetcher
        {:req, "~> 0.5", optional: true},

        # dev & test deps
        {:ex_doc, "~> 0.35", only: :dev}
      ],
      description: @description,
      docs: [
        main: "readme",
        extras: ["README.md"],
        source_url_pattern: "#{@source_url}/blob/v#{@version}/%{path}#L%{line}"
      ],
      elixir: "~> 1.15",
      name: "NoWayJose",
      package: [
        exclude_patterns: [
          ~r/\W\.DS_Store$/,
          ~r/target/
        ],
        files: [
          "README.md",
          "lib",
          "native/nowayjose/.cargo",
          "native/nowayjose/src",
          "native/nowayjose/Cargo*",
          "checksum-*.exs",
          "mix.exs"
        ],
        licenses: ["Apache-2.0"],
        links: %{"GitHub" => @source_url},
        maintainers: ["Sonny Scroggin"]
      ],
      start_permanent: Mix.env() == :prod,
      version: @version
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {NoWayJose.Application, []}
    ]
  end
end
