defmodule NoWayJose do
  @moduledoc """
  Provides functions for signing a map of "claims" into a JWT using
  a signing key.
  """

  @type bits :: pos_integer()
  @type claims :: %{binary() => term()}
  @type output :: :der | :pem
  @type signer :: binary()
  @type token :: binary()

  @doc """
  Generates a signed JWT from the given claims and signer.

  Returns a JWT on success and raises an error on error.
  """
  @spec sign!(claims(), signer()) :: token() | no_return()
  def sign!(claims, signer) do
    case sign(claims, signer) do
      {:ok, token} -> token
      {:error, error} -> raise error
    end
  end

  @doc """
  Generates a signed JWT from the given claims and signer.
  """
  @spec sign(claims(), signer()) :: {:ok, token()} | {:error, term()}
  defdelegate sign(claims, signer), to: NoWayJose.Native

  @doc """
  Generates an RSA private key.
  """
  @spec generate_rsa(bits(), output()) :: binary()
  defdelegate generate_rsa(bits, output), to: NoWayJose.Native
end
