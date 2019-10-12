defmodule NoWayJose do
  def sign!(claims, signer) do
    case sign(claims, signer) do
      {:ok, token} -> token
      {:error, error} -> raise error
    end
  end

  def sign(claims, signer) do
    NoWayJose.Native.sign(claims, signer)
  end
end
