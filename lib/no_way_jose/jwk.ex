defmodule NoWayJose.Jwk do
  @moduledoc """
  Represents a JSON Web Key (JWK).

  Contains the key metadata and raw JSON for use with `verify_with_jwk/3`.
  """

  defstruct [:kid, :kty, :alg, :key_use, :raw]

  @type t :: %__MODULE__{
          kid: String.t() | nil,
          kty: String.t(),
          alg: String.t() | nil,
          key_use: String.t() | nil,
          raw: String.t()
        }
end
