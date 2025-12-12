# NoWayJose

> Rust NIF for JWT signing and verification

![](https://github.com/scrogson/no-way-jose/workflows/CI/badge.svg)

## Features

- Sign and verify JWTs with RSA (RS256, RS512) and ECDSA (ES256, ES384)
- Configurable claims validation (exp, nbf, iss, aud, sub)
- JWKS parsing and key lookup

## Installation

```elixir
def deps do
  [
    {:no_way_jose, "~> 0.3.0"}
  ]
end
```

## Signing

```elixir
# Generate a key
private_key = NoWayJose.generate_rsa(2048, :pem)
# or for ECDSA
private_key = NoWayJose.generate_ec(:p256, :pem)

claims = %{
  "sub" => "user-123",
  "iss" => "https://example.com",
  "exp" => System.system_time(:second) + 3600
}

{:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)
```

## Verification

```elixir
{:ok, claims} = NoWayJose.verify(token,
  alg: :rs256,
  key: public_key,
  format: :pem,
  aud: "my-app",
  iss: "https://example.com"
)
```

### Validation Options

| Option | Description |
|--------|-------------|
| `validate_exp` | Validate expiration (default: true) |
| `validate_nbf` | Validate not-before (default: true) |
| `leeway` | Clock skew tolerance in seconds |
| `iss` | Required issuer(s) |
| `aud` | Required audience(s) |
| `sub` | Required subject |
| `required_claims` | List of required spec claims |

## JWKS

```elixir
# Parse JWKS (you fetch the JSON)
{:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

# Get kid from token header
{:ok, header} = NoWayJose.decode_header(token)

# Find key and verify
{:ok, jwk} = NoWayJose.Jwks.find_key(keys, header.kid)
{:ok, claims} = NoWayJose.verify_with_jwk(token, jwk, aud: "my-app")
```

## Documentation

Documentation can be found at [https://hexdocs.pm/no_way_jose](https://hexdocs.pm/no_way_jose).

## Etymology

A rhyming play on words to indicate that this library does not depend on [JOSE](https://github.com/potatosalad/erlang-jose).

## License

Apache 2.0
