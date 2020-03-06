defmodule NoWayJose do
  @moduledoc """
  Provides functions for signing a map of "claims" into a JWT using
  a signing key.
  """

  @typedoc """
  A map containing the claims to be encoded. Map keys must be strings.
  """
  @type claims :: %{binary() => term()}

  @typedoc """
  DER encoded RSA private key.

  ## Generating a key

      ssh-keygen -m PEM -t rsa -b 4096 -f private.pem

  Make sure not to set a passphrase.


  ## Convert the PEM to DER

      openssl rsa -in private.pem -outform DER -out private.der

  Optionally, you can extract the DER data from a PEM encoded private key in code
  using the following:

      {:ok, key} = File.read("private.pem")
      [{:RSAPrivateKey, der, _}] = :public_key.pem_decode(key)
  """
  @type key :: binary()

  @typedoc """
  JSON Web Token
  """
  @type token :: binary()

  @doc """
  Generates a signed JWT from the given claims and key.

  Returns a JWT on success and raises an error on error.
  """
  @spec sign!(claims(), key()) :: token() | no_return()
  def sign!(claims, key) do
    case sign(claims, key) do
      {:ok, token} -> token
      {:error, error} -> raise error
    end
  end

  @doc """
  Generates a signed JWT from the given claims and key.

  ## Example

      # Get the private signing key
      {:ok, key} = File.read("private.der")

      # Build your claims
      claims = %{
        "exp" => 1571065163,
        "iat" => 1571061563,
        "iss" => "example.com",
        "jti" => "a3a31258-2450-490b-86ed-2b8e67f91e20",
        "nbf" => 1571061563,
        "scopes" => [
          "posts.r+w",
          "comments.r+w"
        ],
        "sub" => "4d3796ca-19e0-40e6-97fe-060c0b7e3ce3"
      }

      # Sign the claims into a JWT
      {:ok, token} = NoWayJose.sign(claims, key)
  """
  @spec sign(claims(), key()) :: {:ok, token()} | {:error, term()}
  def sign(claims, key) do
    NoWayJose.Native.sign(claims, key)
  end
end
