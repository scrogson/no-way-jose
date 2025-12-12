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
    # Note: Providing a PEM key with format: :der causes a panic in jsonwebtoken 10
    # because the DER functions don't return Results - they panic on invalid data.
    # We only test the PEM format mismatch which returns a proper error.

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

  # ============================================================
  # Verification tests
  # ============================================================

  describe "verify/2" do
    test "round-trip sign and verify with RS256" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert {:ok, verified_claims} =
               NoWayJose.verify(token, alg: :rs256, key: public_key, format: :pem)

      assert verified_claims["sub"] == claims["sub"]
      assert verified_claims["iss"] == claims["iss"]
    end

    test "round-trip sign and verify with ES256" do
      private_key = NoWayJose.generate_ec(:p256, :pem)
      public_key = extract_ec_public_key(private_key)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :es256, key: private_key, format: :pem)

      assert {:ok, verified_claims} =
               NoWayJose.verify(token, alg: :es256, key: public_key, format: :pem)

      assert verified_claims["sub"] == claims["sub"]
    end

    test "round-trip sign and verify with ES384" do
      private_key = NoWayJose.generate_ec(:p384, :pem)
      public_key = extract_ec_public_key(private_key)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :es384, key: private_key, format: :pem)

      assert {:ok, verified_claims} =
               NoWayJose.verify(token, alg: :es384, key: public_key, format: :pem)

      assert verified_claims["sub"] == claims["sub"]
    end

    test "rejects expired token" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = %{
        "sub" => "user-1",
        "exp" => System.system_time(:second) - 3600
      }

      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert {:error, :expired_signature} =
               NoWayJose.verify(token, alg: :rs256, key: public_key, format: :pem)
    end

    test "accepts expired token with validation disabled" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = %{
        "sub" => "user-1",
        "exp" => System.system_time(:second) - 3600
      }

      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert {:ok, _claims} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 validate_exp: false
               )
    end

    test "accepts expired token within leeway" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = %{
        "sub" => "user-1",
        "exp" => System.system_time(:second) - 30
      }

      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert {:ok, _claims} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 leeway: 60
               )
    end

    test "rejects immature token (nbf)" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = %{
        "sub" => "user-1",
        "nbf" => System.system_time(:second) + 3600,
        "exp" => System.system_time(:second) + 7200
      }

      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert {:error, :immature_signature} =
               NoWayJose.verify(token, alg: :rs256, key: public_key, format: :pem)
    end

    test "validates issuer" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = valid_claims() |> Map.put("iss", "https://auth.example.com")
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      # Correct issuer
      assert {:ok, _} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 iss: "https://auth.example.com"
               )

      # Wrong issuer
      assert {:error, :invalid_issuer} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 iss: "https://other.example.com"
               )

      # Multiple allowed issuers (list)
      assert {:ok, _} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 iss: ["https://auth.example.com", "https://other.example.com"]
               )
    end

    test "validates audience" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = valid_claims() |> Map.put("aud", "my-app")
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      # Correct audience
      assert {:ok, _} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 aud: "my-app"
               )

      # Wrong audience
      assert {:error, :invalid_audience} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 aud: "other-app"
               )
    end

    test "validates subject" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = valid_claims() |> Map.put("sub", "user-123")
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      # Correct subject
      assert {:ok, _} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 sub: "user-123"
               )

      # Wrong subject
      assert {:error, :invalid_subject} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 sub: "user-456"
               )
    end

    test "validates required claims" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      # Required claim present
      assert {:ok, _} =
               NoWayJose.verify(token,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 required_claims: ["sub"]
               )

      # Create token without aud claim, then require it
      claims_no_aud = Map.delete(valid_claims(), "aud")

      {:ok, token_no_aud} =
        NoWayJose.sign(claims_no_aud, alg: :rs256, key: private_key, format: :pem)

      # Required spec claim missing (only standard JWT claims are enforced)
      assert {:error, :missing_required_claim} =
               NoWayJose.verify(token_no_aud,
                 alg: :rs256,
                 key: public_key,
                 format: :pem,
                 required_claims: ["aud"]
               )
    end

    test "rejects invalid signature" do
      private_key1 = NoWayJose.generate_rsa(2048, :pem)
      private_key2 = NoWayJose.generate_rsa(2048, :pem)
      public_key2 = extract_public_key(private_key2)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key1, format: :pem)

      # Try to verify with wrong key
      assert {:error, :invalid_signature} =
               NoWayJose.verify(token, alg: :rs256, key: public_key2, format: :pem)
    end

    test "rejects invalid token format" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      # Invalid base64 in token parts
      assert {:error, error} =
               NoWayJose.verify("not.a.valid.token", alg: :rs256, key: public_key, format: :pem)

      assert error in [:invalid_token, :invalid_base64]

      assert {:error, error} =
               NoWayJose.verify("garbage", alg: :rs256, key: public_key, format: :pem)

      assert error in [:invalid_token, :invalid_base64]
    end
  end

  describe "verify!/2" do
    test "returns claims on success" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      result = NoWayJose.verify!(token, alg: :rs256, key: public_key, format: :pem)
      assert result["sub"] == claims["sub"]
    end

    test "raises on error" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      public_key = extract_public_key(private_key)

      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) - 3600}
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert_raise ArgumentError, ~r/expired_signature/, fn ->
        NoWayJose.verify!(token, alg: :rs256, key: public_key, format: :pem)
      end
    end
  end

  # ============================================================
  # decode_header tests
  # ============================================================

  describe "decode_header/1" do
    test "extracts header from valid token" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      claims = valid_claims()

      {:ok, token} =
        NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem, kid: "my-key-id")

      assert {:ok, header} = NoWayJose.decode_header(token)
      assert %NoWayJose.Header{} = header
      assert header.alg == "RS256"
      assert header.typ == "JWT"
      assert header.kid == "my-key-id"
    end

    test "handles token without kid" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      claims = valid_claims()

      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      assert {:ok, header} = NoWayJose.decode_header(token)
      assert header.alg == "RS256"
      assert header.kid == nil
    end

    test "returns error for invalid token" do
      assert {:error, :invalid_token} = NoWayJose.decode_header("not-a-token")
    end
  end

  describe "decode_header!/1" do
    test "returns header on success" do
      private_key = NoWayJose.generate_rsa(2048, :pem)
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(claims, alg: :rs256, key: private_key, format: :pem)

      header = NoWayJose.decode_header!(token)
      assert header.alg == "RS256"
    end

    test "raises on invalid token" do
      assert_raise ArgumentError, ~r/invalid_token/, fn ->
        NoWayJose.decode_header!("garbage")
      end
    end
  end

  # ============================================================
  # JWKS tests
  # ============================================================

  describe "Jwks.parse/1" do
    test "parses valid JWKS JSON" do
      jwks_json = """
      {
        "keys": [
          {
            "kty": "RSA",
            "kid": "key-1",
            "alg": "RS256",
            "use": "sig",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
          },
          {
            "kty": "EC",
            "kid": "ec-key-1",
            "alg": "ES256",
            "use": "sig",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
          }
        ]
      }
      """

      assert {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)
      assert length(keys) == 2

      [rsa_key, ec_key] = keys

      assert %NoWayJose.Jwk{} = rsa_key
      assert rsa_key.kid == "key-1"
      assert rsa_key.kty == "RSA"
      assert rsa_key.alg == "RS256"
      # jsonwebtoken formats key_use as "Signature" instead of "sig"
      assert rsa_key.key_use == "Signature"
      assert is_binary(rsa_key.raw)

      assert %NoWayJose.Jwk{} = ec_key
      assert ec_key.kid == "ec-key-1"
      assert ec_key.kty == "EC"
      assert ec_key.alg == "ES256"
    end

    test "returns error for invalid JSON" do
      assert {:error, _} = NoWayJose.Jwks.parse("not json")
    end

    test "returns error for missing keys field" do
      assert {:error, _} = NoWayJose.Jwks.parse(~s({"foo": "bar"}))
    end
  end

  describe "Jwks.find_key/2" do
    test "finds key by kid" do
      jwks_json = sample_jwks_json()
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      assert {:ok, jwk} = NoWayJose.Jwks.find_key(keys, "key-1")
      assert jwk.kid == "key-1"
    end

    test "returns error when key not found" do
      jwks_json = sample_jwks_json()
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      assert :error = NoWayJose.Jwks.find_key(keys, "nonexistent")
    end
  end

  describe "Jwks.find_key!/2" do
    test "returns key on success" do
      jwks_json = sample_jwks_json()
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      jwk = NoWayJose.Jwks.find_key!(keys, "key-1")
      assert jwk.kid == "key-1"
    end

    test "raises when key not found" do
      jwks_json = sample_jwks_json()
      {:ok, keys} = NoWayJose.Jwks.parse(jwks_json)

      assert_raise ArgumentError, ~r/Key not found/, fn ->
        NoWayJose.Jwks.find_key!(keys, "nonexistent")
      end
    end
  end

  # ============================================================
  # Helper functions
  # ============================================================

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

  defp valid_claims do
    %{
      "sub" => "user-1",
      "iss" => "https://auth.example.com",
      "exp" => System.system_time(:second) + 3600,
      "iat" => System.system_time(:second)
    }
  end

  defp extract_public_key(private_pem) do
    [entry] = :public_key.pem_decode(private_pem)
    private_key = :public_key.pem_entry_decode(entry)
    # RSAPrivateKey record: {:RSAPrivateKey, version, modulus, public_exp, priv_exp, ...}
    {:RSAPrivateKey, _version, modulus, public_exponent, _private_exponent, _p, _q, _e1, _e2, _c,
     _other} = private_key

    public_key = {:RSAPublicKey, modulus, public_exponent}
    pem_entry = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)
    :public_key.pem_encode([pem_entry])
  end

  defp extract_ec_public_key(private_pem) do
    [entry] = :public_key.pem_decode(private_pem)
    decoded = :public_key.pem_entry_decode(entry)

    # Handle both PKCS#8 wrapped keys and direct ECPrivateKey
    {ec_private_key, curve_oid} =
      case decoded do
        {:PrivateKeyInfo, _version, {:AlgorithmIdentifier, _oid, {:namedCurve, oid}},
         private_key_der, _attrs} ->
          {:public_key.der_decode(:ECPrivateKey, private_key_der), oid}

        {:ECPrivateKey, _version, _priv, {:namedCurve, oid}, _pub, _} = ec_key ->
          {ec_key, oid}

        {:ECPrivateKey, _version, _priv, {:namedCurve, oid}, _pub} = ec_key ->
          {ec_key, oid}
      end

    # ECPrivateKey: {:ECPrivateKey, version, private_key, params, public_key, asn1_NOVALUE?}
    # The public point is element 4 (0-indexed)
    public_point = elem(ec_private_key, 4)

    ec_public_key = {{:ECPoint, public_point}, {:namedCurve, curve_oid}}

    pem_entry = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, ec_public_key)
    :public_key.pem_encode([pem_entry])
  end

  defp sample_jwks_json do
    """
    {
      "keys": [
        {
          "kty": "RSA",
          "kid": "key-1",
          "alg": "RS256",
          "use": "sig",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e": "AQAB"
        }
      ]
    }
    """
  end
end
