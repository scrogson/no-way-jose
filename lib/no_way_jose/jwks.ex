defmodule NoWayJose.Jwks do
  @moduledoc """
  Functions for working with JSON Web Key Sets (JWKS).

  This module handles parsing JWKS JSON and looking up keys by `kid`.
  The user is responsible for fetching the JWKS JSON from the provider.

  ## Example

      # Fetch JWKS JSON (user's responsibility)
      {:ok, %{body: jwks_json}} = Req.get("https://example.com/.well-known/jwks.json")

      # Parse the JWKS
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      # Get the kid from the token header
      {:ok, header} = NoWayJose.decode_header(token)

      # Find the matching key
      case NoWayJose.Jwks.find_key(keys, header.kid) do
        {:ok, jwk} ->
          NoWayJose.verify_with_jwk(token, jwk, aud: "my-app")
        :error ->
          {:error, :key_not_found}
      end
  """

  alias NoWayJose.Jwk

  @doc """
  Parses a JWKS JSON string into a list of JWK structs.

  ## Example

      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)
  """
  @spec parse(String.t()) :: {:ok, [Jwk.t()]} | {:error, atom()}
  def parse(json) when is_binary(json) do
    NoWayJose.Native.parse_jwks(json)
  end

  @doc """
  Finds a key in the JWKS by its `kid` (key ID).

  ## Example

      {:ok, jwk} = NoWayJose.Jwks.find_key(keys, "key-id-1")
  """
  @spec find_key([Jwk.t()], String.t()) :: {:ok, Jwk.t()} | :error
  def find_key(keys, kid) when is_list(keys) and is_binary(kid) do
    case Enum.find(keys, fn jwk -> jwk.kid == kid end) do
      nil -> :error
      jwk -> {:ok, jwk}
    end
  end

  @doc """
  Finds a key by kid, raising if not found.

  ## Example

      jwk = NoWayJose.Jwks.find_key!(keys, "key-id-1")
  """
  @spec find_key!([Jwk.t()], String.t()) :: Jwk.t() | no_return()
  def find_key!(keys, kid) do
    case find_key(keys, kid) do
      {:ok, jwk} -> jwk
      :error -> raise ArgumentError, "Key not found: #{kid}"
    end
  end
end
