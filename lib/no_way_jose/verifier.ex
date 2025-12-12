defmodule NoWayJose.Verifier do
  @moduledoc """
  Configuration struct for JWT verification.
  """

  defstruct alg: :rs256,
            key: nil,
            format: :pem,
            validate_exp: true,
            validate_nbf: true,
            leeway: 0,
            iss: nil,
            aud: nil,
            sub: nil,
            required_claims: []

  @type t :: %__MODULE__{
          alg: NoWayJose.alg(),
          key: NoWayJose.key() | nil,
          format: NoWayJose.key_format(),
          validate_exp: boolean(),
          validate_nbf: boolean(),
          leeway: non_neg_integer(),
          iss: String.t() | [String.t()] | nil,
          aud: String.t() | [String.t()] | nil,
          sub: String.t() | nil,
          required_claims: [String.t()]
        }
end
