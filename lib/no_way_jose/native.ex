defmodule NoWayJose.Native do
  @moduledoc false

  version = Mix.Project.config()[:version]
  env_config = Application.compile_env(:rustler_precompiled, :force_build, [])

  use RustlerPrecompiled,
    otp_app: :no_way_jose,
    crate: "nowayjose",
    base_url: "https://github.com/scrogson/no-way-jose/releases/download/v#{version}",
    force_build: System.get_env("RUSTLER_BUILD") in ["1", "true"] or env_config[:no_way_jose],
    nif_versions: ["2.14"],
    targets: [
      "aarch64-apple-darwin",
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "arm-unknown-linux-gnueabihf",
      "x86_64-apple-darwin",
      "x86_64-pc-windows-gnu",
      "x86_64-pc-windows-msvc",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl"
    ],
    version: version

  def sign(_claims, _signer), do: nif_error()

  def generate_rsa(_bits, _output), do: nif_error()

  defp nif_error, do: :erlang.nif_error(:nif_not_loaded)
end
