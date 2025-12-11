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
    key = NoWayJose.generate_rsa(2048, :pem)
    assert key =~ "BEGIN RSA PRIVATE KEY"

    key = NoWayJose.generate_rsa(2048, :der)
    assert is_binary(key)

    assert %ErlangError{original: :invalid_variant} ==
             assert_raise(ErlangError, fn ->
               NoWayJose.generate_rsa(2048, :blah)
             end)
  end

  test "sign with invalid options fails", %{claims: claims} do
    key = NoWayJose.generate_rsa(2048, :pem)

    assert {:error, :invalid_rsa_key} =
             NoWayJose.sign(claims, alg: :rs256, key: key, format: :der)

    key = NoWayJose.generate_rsa(2048, :der)

    assert {:error, :invalid_key_format} =
             NoWayJose.sign(claims, alg: :rs256, key: key, format: :pem)
  end

  test "sign with DER encoded private key", %{claims: claims} do
    key = NoWayJose.generate_rsa(4096, :der)
    assert {:ok, token} = NoWayJose.sign(claims, key: key, kid: "a")

    assert {%{"typ" => "JWT", "alg" => "RS512", "kid" => "a"}, ^claims} = decode_token(token)
  end

  test "sign with PEM encoded private key", %{claims: claims} do
    key = NoWayJose.generate_rsa(2048, :pem)
    assert {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: key, format: :pem, kid: "a")

    assert {%{"typ" => "JWT", "alg" => "RS256", "kid" => "a"}, ^claims} = decode_token(token)
  end

  test "generate_ec P-256" do
    key = NoWayJose.generate_ec(:p256, :pem)
    assert key =~ "BEGIN PRIVATE KEY"
    assert is_binary(key)

    key = NoWayJose.generate_ec(:p256, :der)
    assert is_binary(key)
    assert byte_size(key) > 0
  end

  test "generate_ec P-384" do
    key = NoWayJose.generate_ec(:p384, :pem)
    assert key =~ "BEGIN PRIVATE KEY"
    assert is_binary(key)

    key = NoWayJose.generate_ec(:p384, :der)
    assert is_binary(key)
    assert byte_size(key) > 0
  end

  test "generate_ec with invalid curve fails" do
    assert %ErlangError{original: :invalid_variant} ==
             assert_raise(ErlangError, fn ->
               NoWayJose.generate_ec(:p521, :pem)
             end)
  end

  test "sign with ES256 PEM key", %{claims: claims} do
    key = NoWayJose.generate_ec(:p256, :pem)
    assert {:ok, token} = NoWayJose.sign(claims, alg: :es256, key: key, format: :pem, kid: "ec1")

    assert {%{"typ" => "JWT", "alg" => "ES256", "kid" => "ec1"}, ^claims} = decode_token(token)
  end

  test "sign with ES256 DER key", %{claims: claims} do
    key = NoWayJose.generate_ec(:p256, :der)
    assert {:ok, token} = NoWayJose.sign(claims, alg: :es256, key: key, format: :der)

    assert {%{"typ" => "JWT", "alg" => "ES256"}, ^claims} = decode_token(token)
  end

  test "sign with ES384 PEM key", %{claims: claims} do
    key = NoWayJose.generate_ec(:p384, :pem)
    assert {:ok, token} = NoWayJose.sign(claims, alg: :es384, key: key, format: :pem, kid: "ec2")

    assert {%{"typ" => "JWT", "alg" => "ES384", "kid" => "ec2"}, ^claims} = decode_token(token)
  end

  test "sign with ES384 DER key", %{claims: claims} do
    key = NoWayJose.generate_ec(:p384, :der)
    assert {:ok, token} = NoWayJose.sign(claims, alg: :es384, key: key, format: :der)

    assert {%{"typ" => "JWT", "alg" => "ES384"}, ^claims} = decode_token(token)
  end

  test "sign with ES256 using wrong curve fails", %{claims: claims} do
    key = NoWayJose.generate_ec(:p384, :pem)

    assert {:error, :invalid_ecdsa_key} =
             NoWayJose.sign(claims, alg: :es256, key: key, format: :pem)
  end

  test "sign with ES384 using wrong curve fails", %{claims: claims} do
    key = NoWayJose.generate_ec(:p256, :pem)

    assert {:error, :invalid_ecdsa_key} =
             NoWayJose.sign(claims, alg: :es384, key: key, format: :pem)
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
