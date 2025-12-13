defmodule NoWayJose.KeyStore do
  @moduledoc """
  ETS-backed storage for cryptographic keys.

  Keys are stored by namespace and key ID, allowing multiple key sets
  to be managed (e.g., one per JWKS endpoint, one for local signing keys).

  ## Usage

      # Store keys from a JWKS fetcher
      NoWayJose.KeyStore.put("auth0", keys)

      # Lookup a specific key
      {:ok, key} = NoWayJose.KeyStore.get("auth0", "key-id-1")

      # Get all keys for a namespace
      keys = NoWayJose.KeyStore.get_all("auth0")
  """

  @table :no_way_jose_keys

  @doc """
  Stores multiple keys for a namespace.

  Replaces all existing keys for the namespace.
  """
  @spec put(String.t(), [NoWayJose.Key.t()]) :: :ok
  def put(name, keys) when is_binary(name) and is_list(keys) do
    # Delete existing keys for this namespace
    delete(name)

    # Insert new keys
    Enum.each(keys, fn key ->
      put_key(name, key)
    end)

    :ok
  end

  @doc """
  Stores a single key for a namespace.
  """
  @spec put_key(String.t(), NoWayJose.Key.t()) :: :ok
  def put_key(name, %NoWayJose.Key{kid: kid} = key) when is_binary(name) do
    :ets.insert(@table, {{name, kid}, key})
    :ok
  end

  @doc """
  Retrieves a key by namespace and key ID.
  """
  @spec get(String.t(), String.t() | nil) :: {:ok, NoWayJose.Key.t()} | :error
  def get(name, kid) when is_binary(name) do
    case :ets.lookup(@table, {name, kid}) do
      [{{^name, ^kid}, key}] -> {:ok, key}
      [] -> :error
    end
  end

  @doc """
  Retrieves all keys for a namespace.
  """
  @spec get_all(String.t()) :: [NoWayJose.Key.t()]
  def get_all(name) when is_binary(name) do
    match_spec = [
      {{{name, :_}, :"$1"}, [], [:"$1"]}
    ]

    :ets.select(@table, match_spec)
  end

  @doc """
  Deletes all keys for a namespace.
  """
  @spec delete(String.t()) :: :ok
  def delete(name) when is_binary(name) do
    match_spec = [
      {{{name, :_}, :_}, [], [true]}
    ]

    :ets.select_delete(@table, match_spec)
    :ok
  end

  @doc """
  Deletes a specific key.
  """
  @spec delete_key(String.t(), String.t() | nil) :: :ok
  def delete_key(name, kid) when is_binary(name) do
    :ets.delete(@table, {name, kid})
    :ok
  end

  @doc """
  Returns the number of keys stored for a namespace.
  """
  @spec count(String.t()) :: non_neg_integer()
  def count(name) when is_binary(name) do
    match_spec = [
      {{{name, :_}, :_}, [], [true]}
    ]

    :ets.select_count(@table, match_spec)
  end
end
