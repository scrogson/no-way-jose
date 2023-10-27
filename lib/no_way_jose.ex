defmodule NoWayJose do
  @moduledoc """
  Provides functions for signing a map of "claims" into a JWT using
  a signing key.
  """

  require Logger

  @typedoc """
  A map containing the claims to be encoded. Map keys must be strings.
  """
  @type claims :: %{binary() => term()}

  @typedoc """
  Algorithm used in JWT signing.
  """
  @type alg :: :rs512

  @typedoc """
  The format of the provided key.
  """
  @type key_format :: :der | :pem

  @typedoc """
  Key Identifier – Acts as an alias for the key
  """
  @type kid :: nil | binary()

  @type signing_option ::
          {:alg, alg()}
          | {:format, key_format()}
          | {:key, key()}
          | {:kid, kid()}

  @type signing_options :: [signing_option()]

  @typedoc """
  RSA private key.

  The key can be either DER or PEM encoded.

  ## Generating a key

      der = NoWayJose.generate_rsa(4096, :der)
      pem = NoWayJose.generate_rsa(4096, :pem)

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
  @spec sign!(claims(), key() | signing_options()) :: token() | no_return()
  def sign!(claims, opts) do
    case sign(claims, opts) do
      {:ok, token} -> token
      {:error, error} -> raise error
    end
  end

  @doc """
  Generates a signed JWT from the given claims and signing options.

  ## Example

      # Get the private signing key
      {:ok, key} = File.read("private.pem")

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
      {:ok, token} = NoWayJose.sign(claims, alg: :rs512, key: key, format: :pem, kid: "1")
  """
  @spec sign(claims(), signing_options()) :: {:ok, token()} | {:error, term()}
  def sign(claims, key) when is_binary(key) do
    Logger.warn(
      "Passing a binary key to sign/2 is deprecated. Please pass a list of signing options."
    )

    opts = [alg: :rs512, format: :der, key: key]
    NoWayJose.Native.sign(claims, struct(NoWayJose.Signer, opts))
  end

  @spec sign(claims(), signing_options()) :: {:ok, token()} | {:error, term()}
  def sign(claims, opts) when is_list(opts) do
    NoWayJose.Native.sign(claims, struct(NoWayJose.Signer, opts))
  end

  @doc """
  Generates an RSA private key based on the given bit size and format.
  """
  @spec generate_rsa(integer(), key_format()) :: binary()
  def(generate_rsa(bits, format)) do
    NoWayJose.Native.generate_rsa(bits, format)
  end
end
