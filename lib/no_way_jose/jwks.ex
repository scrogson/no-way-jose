defmodule NoWayJose.Jwks do
  @moduledoc """
  Functions for working with JSON Web Key Sets (JWKS).

  This module handles parsing JWKS JSON and looking up keys by `kid`.

  ## Example

      # Fetch JWKS JSON (user's responsibility)
      {:ok, %{body: jwks_json}} = Req.get("https://example.com/.well-known/jwks.json")

      # Parse the JWKS
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      # Get the kid from the token header
      {:ok, header} = NoWayJose.decode_header(token)

      # Find the matching key and verify
      case NoWayJose.Jwks.find_key(keys, header.kid) do
        {:ok, key} ->
          NoWayJose.verify(token, key, aud: "my-app")
        :error ->
          {:error, :key_not_found}
      end

  ## Automatic Fetching

  For automatic key fetching and caching, see `NoWayJose.start_jwks_fetcher/3`.
  """

  alias NoWayJose.Key

  @doc """
  Parses a JWKS JSON string into a list of Key structs.

  ## Example

      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)
  """
  @spec parse(String.t()) :: {:ok, [Key.t()]} | {:error, atom()}
  def parse(json) when is_binary(json) do
    NoWayJose.import(json, :jwks)
  end

  @doc """
  Finds a key in the JWKS by its `kid` (key ID).

  ## Example

      {:ok, key} = NoWayJose.Jwks.find_key(keys, "key-id-1")
  """
  @spec find_key([Key.t()], String.t() | nil) :: {:ok, Key.t()} | :error
  def find_key(keys, kid) when is_list(keys) do
    case Enum.find(keys, fn key -> key.kid == kid end) do
      nil -> :error
      key -> {:ok, key}
    end
  end

  @doc """
  Finds a key by kid, raising if not found.

  ## Example

      key = NoWayJose.Jwks.find_key!(keys, "key-id-1")
  """
  @spec find_key!([Key.t()], String.t() | nil) :: Key.t() | no_return()
  def find_key!(keys, kid) do
    case find_key(keys, kid) do
      {:ok, key} -> key
      :error -> raise ArgumentError, "Key not found: #{kid}"
    end
  end
end
