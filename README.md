# NoWayJose

> Rust NIF for JWT signing

![](https://github.com/scrogson/no-way-jose/workflows/CI/badge.svg)

## Features

In its current state, this library only supports signing JWTs using the `RS512`
algo with a DER encoded RSA private key.

## Installation

```elixir
def deps do
  [
    {:no_way_jose, "~> 0.1.0"}
  ]
end
```

## Generating a key

In order to sign a JWT an RSA private key must be provided. The key must be DER
encoded.

### Generate an RSA public/private key pair

```
ssh-keygen -m PEM -t rsa -b 4096 -f private.pem
# Don't add passphrase
```

### Convert the PEM to DER

```
openssl rsa -in private.pem -outform DER -out private.der
```

Optionally, you can extract the DER data from a PEM encoded private key in code
using the following:

```elixir
{:ok, key} = File.read("private.pem")
[{:RSAPrivateKey, der, _}] = :public_key.pem_decode(key)
```

## Basic usage

```elixir
# Get the private signing key
{:ok, key} = File.read("private.der")

# Build your claims
claims = %{
  "exp" => 1571065163,
  "iat" => 1571061563,
  "iss" => "example.com",
  "jti" => "a3a31258-2450-490b-86ed-2b8e67f91e20",
  "nbf" => 1571061563,
  "scopes" => [
    "posts.r+w",
    "comments.r+w"
  ],
  "sub" => "4d3796ca-19e0-40e6-97fe-060c0b7e3ce3"
}

# Sign the claims into a JWT
{:ok, token} = NoWayJose.sign(claims, key)
```

## Documentation

Documentation can be be found at [https://hexdocs.pm/no_way_jose](https://hexdocs.pm/no_way_jose).

## Roadmap

Please check the [Roadmap](https://github.com/scrogson/no-way-jose/projects/1)
if you're curious about the future of this project.

## Etymology

A rhyming play on words to indicate that this library does not depend on [JOSE](https://github.com/potatosalad/erlang-jose).

## License

Apache 2.0
