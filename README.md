# NoWayJose

> Rust NIF for JWT signing

## Features

In its current state, this library only supports signing JWTs using the `RS512`
algo with an RSA private key.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `no_way_jose` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:no_way_jose, "~> 0.1.0"}
  ]
end
```

## Generating a key

```
ssh-keygen -m PEM -t rsa -b 4096 -f private.pem
# Don't add passphrase
openssl rsa -in private.pem -outform DER -out private.der
```

## Basic usage

```ex
# Get the private signing key
{:ok, key} = File.read("private.key")

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

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/no_way_jose](https://hexdocs.pm/no_way_jose).

## Etymology

A rhyming play on words to indicate that this library does not depend on [JOSE](https://github.com/potatosalad/erlang-jose).

## License

Apache 2.0
