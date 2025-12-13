defmodule NoWayJose do
  @moduledoc """
  JWT signing and verification with unified key handling.

  ## Core API

  NoWayJose provides a simple, unified API for JWT operations:

  ### Importing Keys

      # From PEM (requires algorithm)
      {:ok, key} = NoWayJose.import(pem_data, :pem, alg: :rs256, kid: "key-1")

      # From DER (requires algorithm)
      {:ok, key} = NoWayJose.import(der_data, :der, alg: :es256)

      # From JWK (algorithm inferred, verification-only)
      {:ok, key} = NoWayJose.import(jwk_json, :jwk)

      # From JWKS (returns list of keys)
      {:ok, keys} = NoWayJose.import(jwks_json, :jwks)

  ### Generating Keys

      # RSA keys
      {:ok, key} = NoWayJose.generate(:rs256)
      {:ok, key} = NoWayJose.generate(:rs256, bits: 4096, kid: "my-key")

      # EC keys
      {:ok, key} = NoWayJose.generate(:es256, kid: "ec-key")

  ### Exporting Keys

      # Export as JWK JSON (public key only)
      {:ok, jwk_json} = NoWayJose.export(key, :jwk)

  ### Signing

      {:ok, token} = NoWayJose.sign(key, %{"sub" => "user123"})

  ### Verification

      {:ok, claims} = NoWayJose.verify(key, token, aud: "my-app")

  ## JWKS Fetchers

  For external identity providers, use fetchers to automatically
  refresh keys:

      # Start a fetcher
      :ok = NoWayJose.start_jwks_fetcher("auth0",
        "https://example.auth0.com/.well-known/jwks.json"
      )

      # Verify using stored keys
      {:ok, claims} = NoWayJose.verify_with_stored(token, "auth0", aud: "my-app")

  ## JWKS Export

  Export stored keys as JWKS JSON for `.well-known/jwks.json`:

      jwks_json = NoWayJose.export_jwks("my-app")
  """

  alias NoWayJose.{Key, KeyStore, Native, ValidationOpts}

  @typedoc "A map containing the claims to be encoded"
  @type claims :: %{String.t() => term()}

  @typedoc "JSON Web Token"
  @type token :: String.t()

  @typedoc "Supported algorithms"
  @type alg :: :rs256 | :rs384 | :rs512 | :es256 | :es384 | :ps256 | :ps384 | :ps512 | :eddsa

  @type validation_option ::
          {:validate_exp, boolean()}
          | {:validate_nbf, boolean()}
          | {:leeway, non_neg_integer()}
          | {:iss, String.t() | [String.t()]}
          | {:aud, String.t() | [String.t()]}
          | {:sub, String.t()}
          | {:required_claims, [String.t()]}

  @type validation_options :: [validation_option()]

  # ============================================================================
  # Simplified API (1.0)
  # ============================================================================

  @doc """
  Imports a key from PEM, DER, or JWK format.

  ## Formats

  - `:pem` - PEM-encoded key (requires `alg` option)
  - `:der` - DER-encoded key (requires `alg` option)
  - `:jwk` - JWK JSON (alg inferred from JWK)
  - `:jwks` - JWKS JSON (returns list of keys)

  ## Options

  - `:alg` - Algorithm (required for PEM/DER): :rs256, :rs384, :rs512, :es256, :es384, etc.
  - `:kid` - Key identifier (optional)

  ## Examples

      {:ok, key} = NoWayJose.import(pem, :pem, alg: :rs256, kid: "key-1")
      {:ok, key} = NoWayJose.import(jwk_json, :jwk)
      {:ok, keys} = NoWayJose.import(jwks_json, :jwks)

  ## Notes

  JWK-imported keys are **verification-only** (jsonwebtoken limitation).
  """
  @spec import(binary(), :pem | :der | :jwk | :jwks, keyword()) ::
          {:ok, Key.t()} | {:ok, [Key.t()]} | {:error, atom()}
  def import(data, format, opts \\ [])

  def import(data, :pem, opts) when is_binary(data) do
    alg = Keyword.fetch!(opts, :alg)
    kid = Keyword.get(opts, :kid)

    case alg do
      a when a in [:rs256, :rs384, :rs512, :ps256, :ps384, :ps512] ->
        Native.load_rsa_pem(data, alg, kid)

      a when a in [:es256, :es384] ->
        Native.load_ec_pem(data, alg, kid)

      _ ->
        {:error, :unsupported_algorithm}
    end
  end

  def import(data, :der, opts) when is_binary(data) do
    alg = Keyword.fetch!(opts, :alg)
    kid = Keyword.get(opts, :kid)

    case alg do
      a when a in [:rs256, :rs384, :rs512, :ps256, :ps384, :ps512] ->
        Native.load_rsa_der(data, alg, kid)

      a when a in [:es256, :es384] ->
        Native.load_ec_der(data, alg, kid)

      _ ->
        {:error, :unsupported_algorithm}
    end
  end

  def import(data, :jwk, _opts) when is_binary(data), do: Native.load_jwk(data)
  def import(data, :jwks, _opts) when is_binary(data), do: Native.load_jwks(data)

  @doc """
  Exports a key to the specified format.

  ## Formats

  - `:jwk` - Export as JWK JSON (public key only)
  - `:pem` - Export as PEM string (public key only)
  - `:der` - Export as DER binary (public key only)

  Note: JWK-imported keys can only be exported as JWK.

  ## Examples

      {:ok, jwk_json} = NoWayJose.export(key, :jwk)
      {:ok, pem_string} = NoWayJose.export(key, :pem)
      {:ok, der_binary} = NoWayJose.export(key, :der)
  """
  @spec export(Key.t(), :jwk | :pem | :der) :: {:ok, String.t() | binary()} | {:error, atom()}
  def export(%Key{key_ref: key_ref}, :jwk) do
    Native.export_jwk(key_ref)
  end

  def export(%Key{key_ref: key_ref}, :pem) do
    Native.export_pem(key_ref)
  end

  def export(%Key{key_ref: key_ref}, :der) do
    Native.export_der(key_ref)
  end

  @doc """
  Generates a new key pair.

  Algorithm determines key type:
  - RSA: :rs256, :rs384, :rs512, :ps256, :ps384, :ps512
  - EC: :es256 (P-256), :es384 (P-384)

  ## Options

  - `:bits` - RSA key size (default: 2048, ignored for EC)
  - `:kid` - Key identifier (optional)

  ## Examples

      {:ok, key} = NoWayJose.generate(:rs256)
      {:ok, key} = NoWayJose.generate(:rs256, bits: 4096, kid: "my-key")
      {:ok, key} = NoWayJose.generate(:es256, kid: "ec-key")
  """
  @spec generate(alg(), keyword()) :: {:ok, Key.t()} | {:error, atom()}
  def generate(alg, opts \\ [])

  def generate(alg, opts) when alg in [:rs256, :rs384, :rs512, :ps256, :ps384, :ps512] do
    bits = Keyword.get(opts, :bits, 2048)
    kid = Keyword.get(opts, :kid)
    Native.generate_rsa_key(alg, bits, kid)
  end

  def generate(alg, opts) when alg in [:es256, :es384] do
    kid = Keyword.get(opts, :kid)
    Native.generate_ec_key(alg, kid)
  end

  def generate(_alg, _opts), do: {:error, :unsupported_algorithm}

  # ============================================================================
  # Signing
  # ============================================================================

  @doc """
  Signs claims with a key.

  ## Options

  - `:kid` - Override the key ID in the JWT header (optional)

  ## Examples

      claims = %{"sub" => "user123", "aud" => "my-app"}
      {:ok, token} = NoWayJose.sign(key, claims)

      # With custom kid
      {:ok, token} = NoWayJose.sign(key, claims, kid: "override-kid")
  """
  @spec sign(Key.t(), claims(), keyword()) :: {:ok, token()} | {:error, atom()}
  def sign(%Key{key_ref: key_ref}, claims, opts \\ []) when is_map(claims) do
    kid_override = Keyword.get(opts, :kid)
    Native.sign(claims, key_ref, kid_override)
  end

  @doc """
  Same as `sign/3`, but raises on error.
  """
  @spec sign!(Key.t(), claims(), keyword()) :: token() | no_return()
  def sign!(key, claims, opts \\ []) do
    case sign(key, claims, opts) do
      {:ok, token} -> token
      {:error, reason} -> raise ArgumentError, "Signing failed: #{reason}"
    end
  end

  # ============================================================================
  # Verification
  # ============================================================================

  @doc """
  Verifies a token with a key.

  ## Options

  - `:validate_exp` - Validate expiration claim (default: `true`)
  - `:validate_nbf` - Validate not-before claim (default: `true`)
  - `:leeway` - Clock skew tolerance in seconds (default: `0`)
  - `:iss` - Required issuer(s) - string or list of strings
  - `:aud` - Required audience(s) - string or list of strings
  - `:sub` - Required subject
  - `:required_claims` - List of claim names that must be present

  ## Examples

      {:ok, claims} = NoWayJose.verify(key, token)

      # With validation options
      {:ok, claims} = NoWayJose.verify(key, token,
        aud: "my-app",
        iss: "https://auth.example.com",
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
  """
  @spec verify(Key.t(), token(), validation_options()) :: {:ok, claims()} | {:error, atom()}
  def verify(%Key{key_ref: key_ref}, token, opts \\ []) when is_binary(token) do
    opts = normalize_validation_opts(opts)
    validation_opts = struct(ValidationOpts, opts)
    Native.verify(token, key_ref, validation_opts)
  end

  @doc """
  Same as `verify/3`, but raises on error.
  """
  @spec verify!(Key.t(), token(), validation_options()) :: claims() | no_return()
  def verify!(key, token, opts \\ []) do
    case verify(key, token, opts) do
      {:ok, claims} -> claims
      {:error, reason} -> raise ArgumentError, "Verification failed: #{reason}"
    end
  end

  @doc """
  Verifies a token using stored keys.

  Automatically extracts the `kid` from the token header and looks up
  the matching key from the key store.

  ## Examples

      {:ok, claims} = NoWayJose.verify_with_stored(token, "auth0", aud: "my-app")
  """
  @spec verify_with_stored(token(), String.t(), validation_options()) ::
          {:ok, claims()} | {:error, atom()}
  def verify_with_stored(token, name, opts \\ []) when is_binary(token) and is_binary(name) do
    with {:ok, header} <- decode_header(token),
         {:ok, key} <- KeyStore.get(name, header.kid) do
      verify(key, token, opts)
    else
      :error -> {:error, :key_not_found}
      error -> error
    end
  end

  @doc """
  Same as `verify_with_stored/3`, but raises on error.
  """
  @spec verify_with_stored!(token(), String.t(), validation_options()) :: claims() | no_return()
  def verify_with_stored!(token, name, opts \\ []) do
    case verify_with_stored(token, name, opts) do
      {:ok, claims} -> claims
      {:error, reason} -> raise ArgumentError, "Verification failed: #{reason}"
    end
  end

  # ============================================================================
  # Header Decoding
  # ============================================================================

  @doc """
  Decodes a JWT header without verifying the signature.

  Useful for extracting the `kid` to look up the correct key.

  ## Examples

      {:ok, header} = NoWayJose.decode_header(token)
      # => %NoWayJose.Header{alg: "RS256", typ: "JWT", kid: "key-1"}
  """
  @spec decode_header(token()) :: {:ok, NoWayJose.Header.t()} | {:error, atom()}
  def decode_header(token) when is_binary(token) do
    Native.decode_header(token)
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

  # ============================================================================
  # Key Store Operations
  # ============================================================================

  @doc """
  Stores a key in the key store.

  ## Examples

      :ok = NoWayJose.put_key("my-app", key)
  """
  @spec put_key(String.t(), Key.t()) :: :ok
  def put_key(name, %Key{} = key) when is_binary(name) do
    KeyStore.put_key(name, key)
  end

  @doc """
  Retrieves a key from the key store.

  ## Examples

      {:ok, key} = NoWayJose.get_key("my-app", "key-1")
  """
  @spec get_key(String.t(), String.t() | nil) :: {:ok, Key.t()} | :error
  def get_key(name, kid) when is_binary(name) do
    KeyStore.get(name, kid)
  end

  @doc """
  Retrieves all keys for a namespace.

  ## Examples

      keys = NoWayJose.get_keys("my-app")
  """
  @spec get_keys(String.t()) :: [Key.t()]
  def get_keys(name) when is_binary(name) do
    KeyStore.get_all(name)
  end

  @doc """
  Removes all keys for a namespace.

  ## Examples

      :ok = NoWayJose.delete_keys("my-app")
  """
  @spec delete_keys(String.t()) :: :ok
  def delete_keys(name) when is_binary(name) do
    KeyStore.delete(name)
  end

  # ============================================================================
  # JWKS Fetcher Management
  # ============================================================================

  @doc """
  Starts a JWKS fetcher for an external endpoint.

  ## Options

  - `:refresh_interval` - Refresh period in ms (default: 15 minutes)
  - `:retry_interval` - Retry on failure in ms (default: 30 seconds)
  - `:sync_init` - Block until first fetch completes (default: false)
  - `:http_client` - Custom HTTP client module
  - `:http_opts` - Options passed to the HTTP client

  ## Examples

      # Async start (returns immediately)
      :ok = NoWayJose.start_jwks_fetcher("auth0",
        "https://example.auth0.com/.well-known/jwks.json"
      )

      # Sync start (blocks until keys are loaded)
      :ok = NoWayJose.start_jwks_fetcher("google",
        "https://www.googleapis.com/oauth2/v3/certs",
        sync_init: true
      )
  """
  @spec start_jwks_fetcher(String.t(), String.t(), keyword()) :: :ok | {:error, term()}
  def start_jwks_fetcher(name, url, opts \\ []) when is_binary(name) and is_binary(url) do
    opts = Keyword.merge([name: name, url: url], opts)

    case DynamicSupervisor.start_child(
           NoWayJose.Jwks.FetcherSupervisor,
           {NoWayJose.Jwks.Fetcher, opts}
         ) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Stops a JWKS fetcher.

  ## Examples

      :ok = NoWayJose.stop_jwks_fetcher("auth0")
  """
  @spec stop_jwks_fetcher(String.t()) :: :ok | {:error, :not_found}
  def stop_jwks_fetcher(name) when is_binary(name) do
    case Registry.lookup(NoWayJose.Jwks.Registry, name) do
      [{pid, _}] ->
        DynamicSupervisor.terminate_child(NoWayJose.Jwks.FetcherSupervisor, pid)
        KeyStore.delete(name)
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  # ============================================================================
  # JWKS Export
  # ============================================================================

  @doc """
  Exports stored keys as JWKS JSON.

  Only public key components are exported - private key material
  is never included.

  ## Examples

      # Export keys for a namespace
      jwks_json = NoWayJose.export_jwks("my-app")
      # => ~s({"keys":[{"kty":"RSA","kid":"key-1","n":"...","e":"AQAB"}]})

      # Serve at .well-known/jwks.json
      get "/.well-known/jwks.json" do
        send_resp(conn, 200, NoWayJose.export_jwks("my-app"))
      end
  """
  @spec export_jwks(String.t()) :: String.t()
  def export_jwks(name) when is_binary(name) do
    keys = KeyStore.get_all(name)

    public_keys =
      keys
      |> Enum.map(fn %Key{key_ref: key_ref} ->
        case Native.export_public(key_ref) do
          {:ok, json} -> Jason.decode!(json)
          {:error, _} -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    Jason.encode!(%{"keys" => public_keys})
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp normalize_validation_opts(opts) do
    opts
    |> normalize_list_opt(:iss)
    |> normalize_list_opt(:aud)
  end

  defp normalize_list_opt(opts, key) do
    case Keyword.get(opts, key) do
      nil -> opts
      value when is_binary(value) -> Keyword.put(opts, key, [value])
      value when is_list(value) -> opts
    end
  end
end
