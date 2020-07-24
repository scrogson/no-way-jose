defmodule NoWayJose.Native do
  @moduledoc false

  use Rustler,
    otp_app: :no_way_jose,
    crate: :nowayjose

  def sign(_claims, _signer), do: nif_error()

  def generate_rsa(_bits, _output), do: nif_error()

  defp nif_error, do: :erlang.nif_error(:nif_not_loaded)
end
