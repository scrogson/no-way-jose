defmodule NoWayJose do
  def sign(claims, signer) do
    NoWayJose.Native.sign(claims, signer)
  end
end
