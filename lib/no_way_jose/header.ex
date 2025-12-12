defmodule NoWayJose.Header do
  @moduledoc """
  Represents a decoded JWT header.

  Used to inspect token metadata before verification, particularly
  for extracting the `kid` (key ID) for JWKS key lookup.
  """

  defstruct [:alg, :typ, :kid]

  @type t :: %__MODULE__{
          alg: String.t(),
          typ: String.t() | nil,
          kid: String.t() | nil
        }
end
