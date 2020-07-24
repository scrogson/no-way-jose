defmodule NoWayJose.Signer do
  @moduledoc false

  defstruct alg: :rs512,
            key: nil,
            format: :der,
            kid: nil

  @type t :: %__MODULE__{
          alg: NoWayJose.alg(),
          key: NoWayJose.key(),
          format: NoWayJose.key_format(),
          kid: NoWayJose.kid()
        }
end
