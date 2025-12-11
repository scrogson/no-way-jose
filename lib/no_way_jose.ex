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
  @type alg :: :rs256 | :rs512 | :es256 | :es384

  @typedoc """
  Elliptic curve for EC key generation.
  """
  @type ec_curve :: :p256 | :p384

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

  # this likely needs to change
  # probably need to add some sort of validation mechanism
  @type verify_option ::
          {:alg, alg()}
          | {:format, key_format()}
          | {:key, key()}
          | {:kid, kid()}

  @type verify_options :: [verify_option()]

  @typedoc """
  Private key for signing.

  The key can be either DER or PEM encoded.

  ## RSA keys (RS256, RS512)

      der = NoWayJose.generate_rsa(4096, :der)
      pem = NoWayJose.generate_rsa(4096, :pem)

  ## EC keys (ES256, ES384)

      # P-256 for ES256
      pem = NoWayJose.generate_ec(:p256, :pem)
      der = NoWayJose.generate_ec(:p256, :der)

      # P-384 for ES384
      pem = NoWayJose.generate_ec(:p384, :pem)

  EC keys are generated in PKCS#8 format.
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
    Logger.warning(
      "Passing a binary key to sign/2 is deprecated. Please pass a list of signing options."
    )

    opts = [alg: :rs512, format: :der, key: key]
    NoWayJose.Native.sign(claims, struct(NoWayJose.Signer, opts))
  end

  @spec sign(claims(), signing_options()) :: {:ok, token()} | {:error, term()}
  def sign(claims, opts) when is_list(opts) do
    NoWayJose.Native.sign(claims, struct(NoWayJose.Signer, opts))
  end

  @spec verify(token(), verify_options()) :: {:ok, map()} | {:error, term()}
  def verify(token, opts) when is_list(opts) do
    NoWayJose.Native.verify(token, struct(NoWayJose.Verifier, opts))
  end

  @doc """
  Generates an RSA private key based on the given bit size and format.
  """
  @spec generate_rsa(integer(), key_format()) :: binary()
  def generate_rsa(bits, format) do
    NoWayJose.Native.generate_rsa(bits, format)
  end

  @doc """
  Generates an EC private key for the given curve and format.

  Keys are generated in PKCS#8 format.

  ## Curves

  - `:p256` - NIST P-256 curve, for use with ES256
  - `:p384` - NIST P-384 curve, for use with ES384

  ## Examples

      # Generate P-256 key for ES256
      pem = NoWayJose.generate_ec(:p256, :pem)
      der = NoWayJose.generate_ec(:p256, :der)

      # Generate P-384 key for ES384
      pem = NoWayJose.generate_ec(:p384, :pem)
  """
  @spec generate_ec(ec_curve(), key_format()) :: binary()
  def generate_ec(curve, format) do
    NoWayJose.Native.generate_ec(curve, format)
  end
end
