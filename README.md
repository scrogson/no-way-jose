# NoWayJose

> Rust NIF for JWT signing and verification

![](https://github.com/scrogson/no-way-jose/workflows/CI/badge.svg)

## Features

- Sign and verify JWTs with RSA (RS256, RS384, RS512, PS256, PS384, PS512) and ECDSA (ES256, ES384)
- Configurable claims validation (exp, nbf, iss, aud, sub)
- JWKS fetcher with auto-refresh
- Key store for managing multiple keys
- Export keys as JWKS for `.well-known/jwks.json`

## Installation

```elixir
def deps do
  [
    {:no_way_jose, "~> 1.0"}
  ]
end
```

## Quick Start

```elixir
# Generate a key
{:ok, key} = NoWayJose.generate(:rs256, kid: "my-key")

# Sign
claims = %{"sub" => "user-123", "exp" => System.system_time(:second) + 3600}
{:ok, token} = NoWayJose.sign(key, claims)

# Verify
{:ok, claims} = NoWayJose.verify(key, token)
```

## Key Management

### Generate Keys

```elixir
# RSA (2048-bit default)
{:ok, key} = NoWayJose.generate(:rs256)
{:ok, key} = NoWayJose.generate(:rs256, bits: 4096, kid: "rsa-key")

# ECDSA
{:ok, key} = NoWayJose.generate(:es256, kid: "ec-key")  # P-256
{:ok, key} = NoWayJose.generate(:es384)                  # P-384
```

### Import Keys

```elixir
# From PEM
{:ok, key} = NoWayJose.import(pem_data, :pem, alg: :rs256, kid: "imported")

# From JWK (verification only)
{:ok, key} = NoWayJose.import(jwk_json, :jwk)

# From JWKS
{:ok, keys} = NoWayJose.import(jwks_json, :jwks)
```

### Export Keys

```elixir
# Export public key as JWK
{:ok, jwk_json} = NoWayJose.export(key, :jwk)
```

## Verification Options

| Option | Description |
|--------|-------------|
| `validate_exp` | Validate expiration (default: true) |
| `validate_nbf` | Validate not-before (default: true) |
| `leeway` | Clock skew tolerance in seconds |
| `iss` | Required issuer(s) |
| `aud` | Required audience(s) |
| `sub` | Required subject |
| `required_claims` | List of required claim names |

```elixir
{:ok, claims} = NoWayJose.verify(key, token,
  aud: "my-app",
  iss: "https://auth.example.com",
  leeway: 60
)
```

## JWKS Fetcher

Automatically fetch and refresh keys from external identity providers:

```elixir
# Start a fetcher (keys refresh every 15 minutes)
:ok = NoWayJose.start_jwks_fetcher("auth0",
  "https://example.auth0.com/.well-known/jwks.json"
)

# Verify tokens using stored keys
{:ok, claims} = NoWayJose.verify_with_stored(token, "auth0", aud: "my-app")

# Stop when done
:ok = NoWayJose.stop_jwks_fetcher("auth0")
```

## Serving JWKS

Export your keys for clients:

```elixir
# Store keys
NoWayJose.put_key("my-app", key)

# Serve at /.well-known/jwks.json
get "/.well-known/jwks.json" do
  send_resp(conn, 200, NoWayJose.export_jwks("my-app"))
end
```

## Documentation

Full documentation at [https://hexdocs.pm/no_way_jose](https://hexdocs.pm/no_way_jose).

## Etymology

A rhyming play on words to indicate that this library does not depend on [JOSE](https://github.com/potatosalad/erlang-jose).

## License

Apache 2.0
