defmodule NoWayJose.Jwks.Fetcher do
  @moduledoc """
  GenServer that periodically fetches and caches JWKS from a remote endpoint.

  ## Options

  - `:name` (required) - Unique identifier for this fetcher
  - `:url` (required) - JWKS endpoint URL
  - `:refresh_interval` - Refresh period in ms (default: 15 minutes)
  - `:retry_interval` - Retry period on failure in ms (default: 30 seconds)
  - `:sync_init` - Block until first fetch completes (default: false)
  - `:http_client` - Module implementing `NoWayJose.Jwks.HttpClient` behaviour
  - `:http_opts` - Options passed to the HTTP client

  ## Telemetry Events

  The fetcher emits the following telemetry events:

  - `[:no_way_jose, :jwks, :fetch, :start]` - Fetch started
    - Metadata: `%{name: name, url: url}`

  - `[:no_way_jose, :jwks, :fetch, :stop]` - Fetch completed successfully
    - Measurements: `%{duration: native_time}`
    - Metadata: `%{name: name, url: url, key_count: count}`

  - `[:no_way_jose, :jwks, :fetch, :exception]` - Fetch failed
    - Measurements: `%{duration: native_time}`
    - Metadata: `%{name: name, url: url, reason: reason}`
  """

  use GenServer

  require Logger

  @default_refresh_interval :timer.minutes(15)
  @default_retry_interval :timer.seconds(30)

  defstruct [
    :name,
    :url,
    :refresh_interval,
    :retry_interval,
    :http_client,
    :http_opts
  ]

  @type option ::
          {:name, String.t()}
          | {:url, String.t()}
          | {:refresh_interval, non_neg_integer()}
          | {:retry_interval, non_neg_integer()}
          | {:sync_init, boolean()}
          | {:http_client, module()}
          | {:http_opts, keyword()}

  @type options :: [option()]

  @doc """
  Starts a JWKS fetcher.

  ## Examples

      # Async start (returns immediately, fetches in background)
      {:ok, pid} = NoWayJose.Jwks.Fetcher.start_link(
        name: "auth0",
        url: "https://example.auth0.com/.well-known/jwks.json"
      )

      # Sync start (blocks until first fetch completes)
      {:ok, pid} = NoWayJose.Jwks.Fetcher.start_link(
        name: "google",
        url: "https://www.googleapis.com/oauth2/v3/certs",
        sync_init: true
      )
  """
  @spec start_link(options()) :: GenServer.on_start()
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: via_tuple(name))
  end

  @doc """
  Returns the via tuple for a fetcher.
  """
  @spec via_tuple(String.t()) :: {:via, Registry, {NoWayJose.Jwks.Registry, String.t()}}
  def via_tuple(name) do
    {:via, Registry, {NoWayJose.Jwks.Registry, name}}
  end

  @doc """
  Triggers an immediate refresh of the JWKS.
  """
  @spec refresh(String.t()) :: :ok
  def refresh(name) do
    GenServer.cast(via_tuple(name), :refresh)
  end

  @doc """
  Returns the current state of the fetcher (for debugging).
  """
  @spec get_state(String.t()) :: map()
  def get_state(name) do
    GenServer.call(via_tuple(name), :get_state)
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    name = Keyword.fetch!(opts, :name)
    url = Keyword.fetch!(opts, :url)
    sync_init = Keyword.get(opts, :sync_init, false)

    state = %__MODULE__{
      name: name,
      url: url,
      refresh_interval: Keyword.get(opts, :refresh_interval, @default_refresh_interval),
      retry_interval: Keyword.get(opts, :retry_interval, @default_retry_interval),
      http_client: Keyword.get(opts, :http_client, NoWayJose.Jwks.HttpClient),
      http_opts: Keyword.get(opts, :http_opts, [])
    }

    if sync_init do
      case do_fetch(state) do
        :ok -> {:ok, state}
        {:error, reason} -> {:stop, {:fetch_failed, reason}}
      end
    else
      {:ok, state, {:continue, :fetch}}
    end
  end

  @impl true
  def handle_continue(:fetch, state) do
    handle_fetch(state)
  end

  @impl true
  def handle_cast(:refresh, state) do
    handle_fetch(state)
  end

  @impl true
  def handle_info(:refresh, state) do
    handle_fetch(state)
  end

  @impl true
  def handle_info(:retry, state) do
    handle_fetch(state)
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, Map.from_struct(state), state}
  end

  # Private functions

  defp handle_fetch(state) do
    case do_fetch(state) do
      :ok ->
        schedule_refresh(state.refresh_interval)
        {:noreply, state}

      {:error, _reason} ->
        schedule_retry(state.retry_interval)
        {:noreply, state}
    end
  end

  defp do_fetch(state) do
    %{name: name, url: url, http_client: http_client, http_opts: http_opts} = state

    metadata = %{name: name, url: url}
    start_time = System.monotonic_time()

    :telemetry.execute(
      [:no_way_jose, :jwks, :fetch, :start],
      %{system_time: System.system_time()},
      metadata
    )

    result =
      with {:ok, body} <- http_client.fetch(url, http_opts),
           {:ok, keys} <- NoWayJose.import(body, :jwks) do
        NoWayJose.KeyStore.put(name, keys)
        {:ok, length(keys)}
      end

    duration = System.monotonic_time() - start_time

    case result do
      {:ok, key_count} ->
        :telemetry.execute(
          [:no_way_jose, :jwks, :fetch, :stop],
          %{duration: duration},
          Map.put(metadata, :key_count, key_count)
        )

        Logger.debug("JWKS fetched successfully",
          name: name,
          url: url,
          key_count: key_count
        )

        :ok

      {:error, reason} ->
        :telemetry.execute(
          [:no_way_jose, :jwks, :fetch, :exception],
          %{duration: duration},
          Map.put(metadata, :reason, reason)
        )

        Logger.warning("JWKS fetch failed",
          name: name,
          url: url,
          reason: inspect(reason)
        )

        {:error, reason}
    end
  end

  defp schedule_refresh(interval) do
    Process.send_after(self(), :refresh, interval)
  end

  defp schedule_retry(interval) do
    Process.send_after(self(), :retry, interval)
  end
end
