defmodule NoWayJose.Native do
  @moduledoc false

  version = Mix.Project.config()[:version]
  env_config = Application.compile_env(:rustler_precompiled, :force_build, [])

  use RustlerPrecompiled,
    otp_app: :no_way_jose,
    crate: "nowayjose",
    base_url: "https://github.com/scrogson/no-way-jose/releases/download/v#{version}",
    force_build: System.get_env("NOWAYJOSE_BUILD") in ["1", "true"] or env_config[:no_way_jose],
    nif_versions: ["2.15"],
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

  # Key loading NIFs
  def load_rsa_pem(_pem_data, _alg, _kid), do: nif_error()
  def load_rsa_der(_der_data, _alg, _kid), do: nif_error()
  def load_ec_pem(_pem_data, _alg, _kid), do: nif_error()
  def load_ec_der(_der_data, _alg, _kid), do: nif_error()
  def load_jwk(_json), do: nif_error()
  def load_jwks(_json), do: nif_error()

  # Unified sign/verify NIFs
  def sign(_claims, _key_ref, _kid_override), do: nif_error()
  def verify(_token, _key_ref, _opts), do: nif_error()
  def decode_header(_token), do: nif_error()

  # Export NIFs
  def export_public(_key_ref), do: nif_error()
  def export_jwk(_key_ref), do: nif_error()
  def export_pem(_key_ref), do: nif_error()
  def export_der(_key_ref), do: nif_error()

  # Key generation NIFs
  def generate_rsa_key(_alg, _bits, _kid), do: nif_error()
  def generate_ec_key(_alg, _kid), do: nif_error()

  defp nif_error, do: :erlang.nif_error(:nif_not_loaded)
end
