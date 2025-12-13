defmodule NoWayJose.Key do
  @moduledoc """
  Represents a cryptographic key for signing and verification.

  Key material is stored as an opaque Rust resource - private keys
  never cross the NIF boundary and cannot be logged or inspected.

  ## Loading Keys

  Keys can be loaded from PEM, DER, or JWK formats:

      # PEM format
      {:ok, key} = NoWayJose.import(pem_data, :pem, alg: :rs256, kid: "key-1")

      # JWK format (verification only)
      {:ok, key} = NoWayJose.import(jwk_json, :jwk)

  ## Key Capabilities

  - **PEM/DER keys** can be used for both signing and verification
  - **JWK keys** are verification-only (jsonwebtoken library limitation)

  ## Struct Fields

  - `:kid` - Key identifier (optional)
  - `:alg` - Algorithm atom (`:rs256`, `:es256`, etc.)
  - `:key_use` - Key usage: `"sig"` for signing, `"enc"` for encryption
  - `:key_ref` - Opaque reference to the Rust resource
  """

  @enforce_keys [:alg, :key_ref]
  defstruct [:kid, :alg, :key_use, :key_ref]

  @type alg ::
          :rs256
          | :rs384
          | :rs512
          | :es256
          | :es384
          | :ps256
          | :ps384
          | :ps512
          | :eddsa

  @type t :: %__MODULE__{
          kid: String.t() | nil,
          alg: alg(),
          key_use: String.t() | nil,
          key_ref: reference()
        }

  # Custom inspect to avoid logging key_ref
  defimpl Inspect do
    def inspect(%NoWayJose.Key{kid: kid, alg: alg, key_use: key_use}, _opts) do
      "#NoWayJose.Key<kid: #{inspect(kid)}, alg: #{inspect(alg)}, use: #{inspect(key_use)}>"
    end
  end
end
