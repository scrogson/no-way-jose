defmodule NoWayJose.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Create ETS table before starting supervisor (owned by supervisor process)
    :ets.new(:no_way_jose_keys, [
      :named_table,
      :public,
      :set,
      read_concurrency: true
    ])

    children = [
      {Registry, keys: :unique, name: NoWayJose.Jwks.Registry},
      {DynamicSupervisor, name: NoWayJose.Jwks.FetcherSupervisor, strategy: :one_for_one}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: NoWayJose.Supervisor)
  end
end
