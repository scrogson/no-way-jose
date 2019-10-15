defmodule NoWayJose.TestUtils do
  use Rustler,
    otp_app: :no_way_jose,
    crate: :nowayjose_testutils

  @type output :: :der | :pem

  def generate_rsa(_bits, _output), do: :erlang.nif_error(:nif_not_loaded)
end
