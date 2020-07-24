defmodule NoWayJoseTest do
  use ExUnit.Case
  doctest NoWayJose

  setup do
    {:ok,
     claims: %{
       "exp" => 1_570_911_685,
       "sub" => "1",
       "iss" => "example.com",
       "scopes" => ["ADMIN"],
       "nested" => %{
         "a" => 1,
         "b" => %{
           "c" => [nil, [1, "string"]]
         }
       }
     }}
  end

  test "generate_rsa" do
    key = NoWayJose.generate_rsa(4096, :pem)
    assert key =~ "BEGIN RSA PRIVATE KEY"
    key = NoWayJose.generate_rsa(4096, :der)
    assert is_binary(key)

    assert :invalid_variant = NoWayJose.generate_rsa(4096, :blah)
  end

  test "sign with invalid options fails", %{claims: claims} do
    key = NoWayJose.generate_rsa(4096, :pem)
    assert {:error, :invalid_rsa_key} = NoWayJose.sign(claims, key: key, format: :der)

    key = NoWayJose.generate_rsa(4096, :der)

    assert {:error, :invalid_key_format} = NoWayJose.sign(claims, key: key, format: :pem)
  end

  test "sign with DER encoded private key", %{claims: claims} do
    key = NoWayJose.generate_rsa(4096, :der)
    assert {:ok, token} = NoWayJose.sign(claims, key: key, kid: "a")

    assert {%{"typ" => "JWT", "alg" => "RS512", "kid" => "a"}, ^claims} = decode_token(token)
  end

  test "sign with PEM encoded private key", %{claims: claims} do
    key = NoWayJose.generate_rsa(4096, :pem)
    assert {:ok, token} = NoWayJose.sign(claims, key: key, format: :pem, kid: "a")

    assert {%{"typ" => "JWT", "alg" => "RS512", "kid" => "a"}, ^claims} = decode_token(token)
  end

  defp decode_token(token) do
    [header, payload, _signature] = String.split(token, ".")

    header =
      header
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    payload =
      payload
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    {header, payload}
  end
end
