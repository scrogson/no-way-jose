defmodule NoWayJose.Native do
  use Rustler,
    otp_app: :no_way_jose,
    crate: :nowayjose

  def sign(claims, signer), do: nif_error()

  defp nif_error, do: :erlang.nif_error(:nif_not_loaded)
end
