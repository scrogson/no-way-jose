defmodule NoWayJose.Jwks.HttpClient do
  @moduledoc """
  Behaviour for HTTP clients used by JWKS fetchers.

  The default implementation uses Req (if available). You can provide
  a custom implementation by passing the `:http_client` option to
  `NoWayJose.start_jwks_fetcher/3`.

  ## Options

  The following options are supported by the default implementation:

  - `:timeout` - Connection and receive timeout in milliseconds (default: 30000)
  - `:connect_options` - Options passed to `Req`'s `:connect_options`, including:
    - `:transport_opts` - Options for the underlying socket, such as SSL settings

  ## SSL Configuration

  To disable SSL certificate verification (useful for self-signed certificates
  in development/staging environments):

      NoWayJose.start_jwks_fetcher("auth0", url,
        http_opts: [
          connect_options: [
            transport_opts: [verify: :verify_none]
          ]
        ]
      )

  To use a custom CA certificate:

      NoWayJose.start_jwks_fetcher("auth0", url,
        http_opts: [
          connect_options: [
            transport_opts: [
              verify: :verify_peer,
              cacertfile: "/path/to/ca-cert.pem"
            ]
          ]
        ]
      )

  ## Custom Implementation

  To implement a custom HTTP client:

      defmodule MyApp.HttpClient do
        @behaviour NoWayJose.Jwks.HttpClient

        @impl true
        def fetch(url, opts) do
          case HTTPoison.get(url, [], opts) do
            {:ok, %{status_code: 200, body: body}} -> {:ok, body}
            {:ok, %{status_code: status}} -> {:error, {:http_error, status}}
            {:error, reason} -> {:error, reason}
          end
        end
      end

  Then use it:

      NoWayJose.start_jwks_fetcher("auth0", url,
        http_client: MyApp.HttpClient
      )
  """

  @type url :: String.t()
  @type opts :: keyword()
  @type body :: String.t()
  @type error :: {:http_error, non_neg_integer()} | term()

  @doc """
  Fetches the content at the given URL.

  Should return `{:ok, body}` on success (HTTP 200),
  or `{:error, reason}` on failure.
  """
  @callback fetch(url(), opts()) :: {:ok, body()} | {:error, error()}

  @doc """
  Default implementation using Req.

  Falls back to a simple error if Req is not available.
  """
  @spec fetch(url(), opts()) :: {:ok, body()} | {:error, error()}
  def fetch(url, opts \\ []) do
    if Code.ensure_loaded?(Req) do
      fetch_with_req(url, opts)
    else
      {:error, :req_not_available}
    end
  end

  defp fetch_with_req(url, opts) do
    timeout = Keyword.get(opts, :timeout, 30_000)
    connect_options = Keyword.get(opts, :connect_options, [])

    # Merge timeout into connect_options, preserving any user-provided options
    connect_options = Keyword.put_new(connect_options, :timeout, timeout)

    req_opts = [
      receive_timeout: timeout,
      connect_options: connect_options
    ]

    case Req.get(url, req_opts) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        {:ok, body}

      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, Jason.encode!(body)}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
