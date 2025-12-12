defmodule NoWayJose do
  @moduledoc """
  Provides functions for signing and verifying JWTs.

  ## Signing

  Sign a map of claims into a JWT using RSA or EC keys:

      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

  ## Verification

  Verify a JWT and extract claims:

      {:ok, claims} = NoWayJose.verify(token,
        alg: :rs256,
        key: public_key,
        format: :pem,
        aud: "my-app",
        iss: "https://auth.example.com"
      )

  ## JWKS Workflow

  For OIDC/OAuth2 providers that publish JWKS:

      # 1. Fetch JWKS JSON (your responsibility)
      {:ok, %{body: jwks_json}} = Req.get("https://example.com/.well-known/jwks.json")

      # 2. Parse the JWKS
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      # 3. Get the kid from the token header
      {:ok, header} = NoWayJose.decode_header(token)

      # 4. Find the matching key and verify
      {:ok, jwk} = NoWayJose.Jwks.find_key(keys, header.kid)
      {:ok, claims} = NoWayJose.verify_with_jwk(token, jwk, aud: "my-app")
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

  @type verify_option ::
          {:alg, alg()}
          | {:format, key_format()}
          | {:key, key()}
          | {:validate_exp, boolean()}
          | {:validate_nbf, boolean()}
          | {:leeway, non_neg_integer()}
          | {:iss, String.t() | [String.t()]}
          | {:aud, String.t() | [String.t()]}
          | {:sub, String.t()}
          | {:required_claims, [String.t()]}

  @type verify_options :: [verify_option()]

  @type validation_option ::
          {:validate_exp, boolean()}
          | {:validate_nbf, boolean()}
          | {:leeway, non_neg_integer()}
          | {:iss, String.t() | [String.t()]}
          | {:aud, String.t() | [String.t()]}
          | {:sub, String.t()}
          | {:required_claims, [String.t()]}

  @type validation_options :: [validation_option()]

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

  @doc """
  Verifies a JWT and returns the claims on success.

  ## Options

  - `:alg` - Algorithm (`:rs256`, `:rs512`, `:es256`, `:es384`)
  - `:key` - Public key for verification
  - `:format` - Key format (`:pem` or `:der`)
  - `:validate_exp` - Validate expiration claim (default: `true`)
  - `:validate_nbf` - Validate not-before claim (default: `true`)
  - `:leeway` - Clock skew tolerance in seconds (default: `0`)
  - `:iss` - Required issuer(s) - string or list of strings
  - `:aud` - Required audience(s) - string or list of strings
  - `:sub` - Required subject
  - `:required_claims` - List of claim names that must be present

  ## Examples

      # Basic verification
      {:ok, claims} = NoWayJose.verify(token, alg: :rs256, key: public_key, format: :pem)

      # With claim validation
      {:ok, claims} = NoWayJose.verify(token,
        alg: :rs256,
        key: public_key,
        format: :pem,
        aud: "my-app",
        iss: ["https://auth.example.com", "https://auth2.example.com"],
        leeway: 60
      )

  ## Errors

  Returns `{:error, reason}` where reason is one of:

  - `:invalid_token` - Malformed JWT
  - `:invalid_signature` - Signature verification failed
  - `:expired_signature` - Token has expired
  - `:immature_signature` - Token not yet valid (nbf)
  - `:invalid_issuer` - Issuer doesn't match
  - `:invalid_audience` - Audience doesn't match
  - `:invalid_subject` - Subject doesn't match
  - `:missing_required_claim` - Required claim not present
  - `:invalid_rsa_key` - Invalid RSA public key
  - `:invalid_ecdsa_key` - Invalid EC public key
  """
  @spec verify(token(), verify_options()) :: {:ok, map()} | {:error, atom()}
  def verify(token, opts) when is_list(opts) do
    opts = normalize_validation_opts(opts)
    NoWayJose.Native.verify(token, struct(NoWayJose.Verifier, opts))
  end

  @doc """
  Same as `verify/2`, but raises on error.
  """
  @spec verify!(token(), verify_options()) :: map() | no_return()
  def verify!(token, opts) do
    case verify(token, opts) do
      {:ok, claims} -> claims
      {:error, reason} -> raise ArgumentError, "Verification failed: #{reason}"
    end
  end

  @doc """
  Decodes a JWT header without verifying the signature.

  This is useful for extracting the `kid` (key ID) to look up the
  correct key from a JWKS before verification.

  ## Example

      {:ok, header} = NoWayJose.decode_header(token)
      # => %NoWayJose.Header{alg: "RS256", typ: "JWT", kid: "key-1"}
  """
  @spec decode_header(token()) :: {:ok, NoWayJose.Header.t()} | {:error, atom()}
  def decode_header(token) when is_binary(token) do
    NoWayJose.Native.decode_header(token)
  end

  @doc """
  Same as `decode_header/1`, but raises on error.
  """
  @spec decode_header!(token()) :: NoWayJose.Header.t() | no_return()
  def decode_header!(token) do
    case decode_header(token) do
      {:ok, header} -> header
      {:error, reason} -> raise ArgumentError, "Failed to decode header: #{reason}"
    end
  end

  @doc """
  Verifies a JWT using a JWK (JSON Web Key).

  The algorithm is automatically determined from the JWK's `alg` field
  or inferred from the key type.

  ## Options

  Same validation options as `verify/2`, except `:alg`, `:key`, and `:format`
  which are determined by the JWK.

  ## Example

      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)
      {:ok, jwk} = NoWayJose.Jwks.find_key(keys, "key-id-1")
      {:ok, claims} = NoWayJose.verify_with_jwk(token, jwk, aud: "my-app")
  """
  @spec verify_with_jwk(token(), NoWayJose.Jwk.t(), validation_options()) ::
          {:ok, map()} | {:error, atom()}
  def verify_with_jwk(token, %NoWayJose.Jwk{raw: raw}, opts \\ []) when is_list(opts) do
    opts = normalize_validation_opts(opts)
    validation_opts = struct(NoWayJose.ValidationOpts, opts)
    NoWayJose.Native.verify_with_jwk(token, raw, validation_opts)
  end

  @doc """
  Same as `verify_with_jwk/3`, but raises on error.
  """
  @spec verify_with_jwk!(token(), NoWayJose.Jwk.t(), validation_options()) :: map() | no_return()
  def verify_with_jwk!(token, jwk, opts \\ []) do
    case verify_with_jwk(token, jwk, opts) do
      {:ok, claims} -> claims
      {:error, reason} -> raise ArgumentError, "Verification failed: #{reason}"
    end
  end

  # Normalize iss and aud to always be lists (or nil)
  defp normalize_validation_opts(opts) do
    opts
    |> normalize_opt(:iss)
    |> normalize_opt(:aud)
  end

  defp normalize_opt(opts, key) do
    case Keyword.get(opts, key) do
      nil -> opts
      value when is_binary(value) -> Keyword.put(opts, key, [value])
      value when is_list(value) -> opts
    end
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
