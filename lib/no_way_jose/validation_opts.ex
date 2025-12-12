defmodule NoWayJose.ValidationOpts do
  @moduledoc false

  defstruct validate_exp: true,
            validate_nbf: true,
            leeway: 0,
            iss: nil,
            aud: nil,
            sub: nil,
            required_claims: []

  @type t :: %__MODULE__{
          validate_exp: boolean(),
          validate_nbf: boolean(),
          leeway: non_neg_integer(),
          iss: [String.t()] | nil,
          aud: [String.t()] | nil,
          sub: String.t() | nil,
          required_claims: [String.t()]
        }
end
