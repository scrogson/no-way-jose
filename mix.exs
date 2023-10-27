defmodule NoWayJose.MixProject do
  use Mix.Project

  @description "Rust NIF for signing JWTs"
  @source_url "https://github.com/scrogson/no-way-jose"
  @version "0.3.0"

  def project do
    [
      app: :no_way_jose,
      deps: [
        {:jason, "~> 1.0"},
        {:rustler, "~> 0.30", optional: true},
        {:rustler_precompiled, "~> 0.7"},

        # dev & test deps
        {:ex_doc, "~> 0.21", only: :dev}
      ],
      description: @description,
      docs: [
        main: "readme",
        extras: ["README.md"],
        source_url_pattern: "#{@source_url}/blob/v#{@version}/%{path}#L%{line}"
      ],
      elixir: "~> 1.8",
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

  def application, do: [extra_applications: [:logger]]
end
