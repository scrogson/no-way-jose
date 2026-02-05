defmodule NoWayJoseTest do
  use ExUnit.Case, async: true

  # Generate keys once for the entire test module
  setup_all do
    {:ok, rsa_key} = NoWayJose.generate(:rs256, kid: "test-rsa")
    {:ok, rsa_key_no_kid} = NoWayJose.generate(:rs256)
    {:ok, ec_key} = NoWayJose.generate(:es256, kid: "test-ec")

    %{rsa_key: rsa_key, rsa_key_no_kid: rsa_key_no_kid, ec_key: ec_key}
  end

  # ============================================================
  # Key Generation tests
  # ============================================================

  describe "generate/2" do
    test "generates RSA key with default bits" do
      assert {:ok, key} = NoWayJose.generate(:rs256)
      assert %NoWayJose.Key{} = key
      assert key.alg == :rs256
      assert key.key_use == "sig"
    end

    test "generates RSA key with custom bits and kid" do
      assert {:ok, key} = NoWayJose.generate(:rs256, bits: 4096, kid: "my-rsa-key")
      assert key.alg == :rs256
      assert key.kid == "my-rsa-key"
    end

    @tag :slow
    test "generates all RSA algorithm variants" do
      for alg <- [:rs384, :rs512, :ps256, :ps384, :ps512] do
        assert {:ok, key} = NoWayJose.generate(alg)
        assert key.alg == alg
      end
    end

    test "generates EC P-256 key" do
      assert {:ok, key} = NoWayJose.generate(:es256)
      assert key.alg == :es256
    end

    test "generates EC P-384 key with kid" do
      assert {:ok, key} = NoWayJose.generate(:es384, kid: "my-ec-key")
      assert key.alg == :es384
      assert key.kid == "my-ec-key"
    end

    test "generated RSA key can sign and verify", %{rsa_key: key} do
      claims = valid_claims()

      assert {:ok, token} = NoWayJose.sign(key, claims)
      assert {:ok, decoded} = NoWayJose.verify(key, token)
      assert decoded["sub"] == "user-1"
    end

    test "generated EC key can sign and verify", %{ec_key: key} do
      claims = valid_claims()

      assert {:ok, token} = NoWayJose.sign(key, claims)
      assert {:ok, decoded} = NoWayJose.verify(key, token)
      assert decoded["sub"] == "user-1"
    end

    test "returns error for unsupported algorithm" do
      assert {:error, :unsupported_algorithm} = NoWayJose.generate(:hs256)
    end
  end

  # ============================================================
  # Signing tests
  # ============================================================

  describe "sign/3" do
    test "signs claims with RSA key", %{rsa_key: key} do
      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) + 3600}
      assert {:ok, token} = NoWayJose.sign(key, claims)

      {header, payload} = decode_token(token)
      assert header["alg"] == "RS256"
      assert header["kid"] == "test-rsa"
      assert payload["sub"] == "user-1"
    end

    test "signs claims with EC key", %{ec_key: key} do
      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) + 3600}
      assert {:ok, token} = NoWayJose.sign(key, claims)

      {header, _payload} = decode_token(token)
      assert header["alg"] == "ES256"
      assert header["kid"] == "test-ec"
    end

    test "allows kid override", %{rsa_key: key} do
      claims = %{"sub" => "user-1"}
      {:ok, token} = NoWayJose.sign(key, claims, kid: "override")

      {header, _payload} = decode_token(token)
      assert header["kid"] == "override"
    end
  end

  describe "sign!/3" do
    test "returns token on success", %{rsa_key: key} do
      claims = %{"sub" => "user-1"}
      token = NoWayJose.sign!(key, claims)
      assert is_binary(token)
    end
  end

  # ============================================================
  # Verification tests
  # ============================================================

  describe "verify/3" do
    test "round-trip sign and verify with RSA", %{rsa_key: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:ok, verified_claims} = NoWayJose.verify(key, token)
      assert verified_claims["sub"] == claims["sub"]
      assert verified_claims["iss"] == claims["iss"]
    end

    test "round-trip sign and verify with EC", %{ec_key: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:ok, verified_claims} = NoWayJose.verify(key, token)
      assert verified_claims["sub"] == claims["sub"]
    end

    test "verify with exported JWK (RSA)", %{rsa_key: signing_key} do
      {:ok, jwk_json} = NoWayJose.export(signing_key, :jwk)
      {:ok, verify_key} = NoWayJose.import(jwk_json, :jwk)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(signing_key, claims)

      assert {:ok, verified_claims} = NoWayJose.verify(verify_key, token)
      assert verified_claims["sub"] == claims["sub"]
    end

    test "verify with exported JWK (EC)", %{ec_key: signing_key} do
      {:ok, jwk_json} = NoWayJose.export(signing_key, :jwk)
      {:ok, verify_key} = NoWayJose.import(jwk_json, :jwk)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(signing_key, claims)

      assert {:ok, verified_claims} = NoWayJose.verify(verify_key, token)
      assert verified_claims["sub"] == claims["sub"]
    end

    test "rejects expired token", %{rsa_key: key} do
      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) - 3600}
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:error, :expired_signature} = NoWayJose.verify(key, token)
    end

    test "accepts expired token with validation disabled", %{rsa_key: key} do
      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) - 3600}
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:ok, _claims} = NoWayJose.verify(key, token, validate_exp: false)
    end

    test "accepts expired token within leeway", %{rsa_key: key} do
      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) - 30}
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:ok, _claims} = NoWayJose.verify(key, token, leeway: 60)
    end

    test "rejects immature token (nbf)", %{rsa_key: key} do
      claims = %{
        "sub" => "user-1",
        "nbf" => System.system_time(:second) + 3600,
        "exp" => System.system_time(:second) + 7200
      }

      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:error, :immature_signature} = NoWayJose.verify(key, token)
    end

    test "validates issuer", %{rsa_key: key} do
      claims = valid_claims() |> Map.put("iss", "https://auth.example.com")
      {:ok, token} = NoWayJose.sign(key, claims)

      # Correct issuer
      assert {:ok, _} = NoWayJose.verify(key, token, iss: "https://auth.example.com")

      # Wrong issuer
      assert {:error, :invalid_issuer} =
               NoWayJose.verify(key, token, iss: "https://other.example.com")

      # Multiple allowed issuers (list)
      assert {:ok, _} =
               NoWayJose.verify(key, token,
                 iss: ["https://auth.example.com", "https://other.example.com"]
               )
    end

    test "validates audience", %{rsa_key: key} do
      claims = valid_claims() |> Map.put("aud", "my-app")
      {:ok, token} = NoWayJose.sign(key, claims)

      # Correct audience
      assert {:ok, _} = NoWayJose.verify(key, token, aud: "my-app")

      # Wrong audience
      assert {:error, :invalid_audience} = NoWayJose.verify(key, token, aud: "other-app")
    end

    test "skips audience validation when aud option not provided", %{rsa_key: key} do
      claims = valid_claims() |> Map.put("aud", "my-app")
      {:ok, token} = NoWayJose.sign(key, claims)

      # When no aud option is provided, audience validation is skipped
      assert {:ok, decoded} = NoWayJose.verify(key, token)
      assert decoded["aud"] == "my-app"
    end

    test "validates subject", %{rsa_key: key} do
      claims = valid_claims() |> Map.put("sub", "user-123")
      {:ok, token} = NoWayJose.sign(key, claims)

      # Correct subject
      assert {:ok, _} = NoWayJose.verify(key, token, sub: "user-123")

      # Wrong subject
      assert {:error, :invalid_subject} = NoWayJose.verify(key, token, sub: "user-456")
    end

    test "validates required claims", %{rsa_key: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

      # Required claim present
      assert {:ok, _} = NoWayJose.verify(key, token, required_claims: ["sub"])

      # Create token without aud claim, then require it
      claims_no_aud = Map.delete(valid_claims(), "aud")
      {:ok, token_no_aud} = NoWayJose.sign(key, claims_no_aud)

      # Required spec claim missing
      assert {:error, :missing_required_claim} =
               NoWayJose.verify(key, token_no_aud, required_claims: ["aud"])
    end

    test "rejects invalid signature", %{rsa_key: key1} do
      # Need a second key for this test
      {:ok, key2} = NoWayJose.generate(:rs256)

      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key1, claims)

      # Try to verify with wrong key
      assert {:error, :invalid_signature} = NoWayJose.verify(key2, token)
    end

    test "rejects invalid token format", %{rsa_key: key} do
      assert {:error, error} = NoWayJose.verify(key, "not.a.valid.token")
      assert error in [:invalid_token, :invalid_base64, :unknown_error]

      assert {:error, error} = NoWayJose.verify(key, "garbage")
      assert error in [:invalid_token, :invalid_base64, :unknown_error]
    end
  end

  describe "verify!/3" do
    test "returns claims on success", %{rsa_key: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

      result = NoWayJose.verify!(key, token)
      assert result["sub"] == claims["sub"]
    end

    test "raises on error", %{rsa_key: key} do
      claims = %{"sub" => "user-1", "exp" => System.system_time(:second) - 3600}
      {:ok, token} = NoWayJose.sign(key, claims)

      assert_raise ArgumentError, ~r/expired_signature/, fn ->
        NoWayJose.verify!(key, token)
      end
    end
  end

  # ============================================================
  # decode_header tests
  # ============================================================

  describe "decode_header/1" do
    test "extracts header from valid token", %{rsa_key: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:ok, header} = NoWayJose.decode_header(token)
      assert %NoWayJose.Header{} = header
      assert header.alg == "RS256"
      assert header.typ == "JWT"
      assert header.kid == "test-rsa"
    end

    test "handles token without kid", %{rsa_key_no_kid: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

      assert {:ok, header} = NoWayJose.decode_header(token)
      assert header.alg == "RS256"
      assert header.kid == nil
    end

    test "returns error for invalid token" do
      assert {:error, :invalid_token} = NoWayJose.decode_header("not-a-token")
    end
  end

  describe "decode_header!/1" do
    test "returns header on success", %{rsa_key: key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(key, claims)

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
  # import/3 tests
  # ============================================================

  describe "import/3" do
    test "imports JWK" do
      jwk_json = sample_jwk_json()
      assert {:ok, key} = NoWayJose.import(jwk_json, :jwk)
      assert key.kid == "key-1"
    end

    test "imports JWKS" do
      jwks_json = sample_jwks_json()
      assert {:ok, keys} = NoWayJose.import(jwks_json, :jwks)
      assert length(keys) == 1
      assert hd(keys).kid == "key-1"
    end

    test "returns error for unsupported algorithm" do
      # JWK import doesn't need alg option, so test PEM import instead
      # Since we can't generate raw PEM anymore, just test the error case
      assert {:error, :unsupported_algorithm} = NoWayJose.import("dummy", :pem, alg: :hs256)
    end

    test "raises on missing alg for PEM" do
      assert_raise KeyError, fn ->
        NoWayJose.import("dummy", :pem, [])
      end
    end
  end

  # ============================================================
  # export/2 tests
  # ============================================================

  describe "export/2" do
    test "exports generated RSA key as JWK", %{rsa_key: key} do
      assert {:ok, jwk_json} = NoWayJose.export(key, :jwk)

      jwk = Jason.decode!(jwk_json)
      assert jwk["kty"] == "RSA"
      assert jwk["kid"] == "test-rsa"
      assert jwk["use"] == "sig"
      # Should not contain private key material
      refute Map.has_key?(jwk, "d")
    end

    test "exports generated EC key as JWK", %{ec_key: key} do
      assert {:ok, jwk_json} = NoWayJose.export(key, :jwk)

      jwk = Jason.decode!(jwk_json)
      assert jwk["kty"] == "EC"
      assert jwk["kid"] == "test-ec"
      assert jwk["crv"] == "P-256"
      # Should not contain private key material
      refute Map.has_key?(jwk, "d")
    end

    test "exports imported JWK key" do
      jwk_json = sample_jwk_json()
      {:ok, key} = NoWayJose.import(jwk_json, :jwk)
      assert {:ok, exported} = NoWayJose.export(key, :jwk)

      # Should return the public JWK
      jwk = Jason.decode!(exported)
      assert jwk["kty"] == "RSA"
    end

    test "exports RSA key as PEM", %{rsa_key: key} do
      assert {:ok, pem} = NoWayJose.export(key, :pem)
      assert String.starts_with?(pem, "-----BEGIN RSA PUBLIC KEY-----")
    end

    test "exports RSA key as DER", %{rsa_key: key} do
      assert {:ok, der} = NoWayJose.export(key, :der)
      assert is_binary(der)
      # DER should be shorter than PEM (no base64 overhead)
      {:ok, pem} = NoWayJose.export(key, :pem)
      assert byte_size(der) < byte_size(pem)
    end

    test "exports EC key as PEM", %{ec_key: key} do
      assert {:ok, pem} = NoWayJose.export(key, :pem)
      assert String.starts_with?(pem, "-----BEGIN PUBLIC KEY-----")
    end

    test "exports EC key as DER", %{ec_key: key} do
      assert {:ok, der} = NoWayJose.export(key, :der)
      assert is_binary(der)
    end

    test "returns error for JWK-imported key exported as PEM" do
      jwk_json = sample_jwk_json()
      {:ok, key} = NoWayJose.import(jwk_json, :jwk)
      assert {:error, :unsupported_key_type} = NoWayJose.export(key, :pem)
    end

    test "round-trip: generate -> export -> import -> verify", %{rsa_key: signing_key} do
      # Sign a token
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(signing_key, claims)

      # Export as JWK
      {:ok, jwk_json} = NoWayJose.export(signing_key, :jwk)

      # Import the JWK (verification-only)
      {:ok, verify_key} = NoWayJose.import(jwk_json, :jwk)

      # Verify with imported key
      assert {:ok, decoded} = NoWayJose.verify(verify_key, token)
      assert decoded["sub"] == "user-1"
    end

    test "round-trip with EC key", %{ec_key: signing_key} do
      claims = valid_claims()
      {:ok, token} = NoWayJose.sign(signing_key, claims)

      {:ok, jwk_json} = NoWayJose.export(signing_key, :jwk)
      {:ok, verify_key} = NoWayJose.import(jwk_json, :jwk)

      assert {:ok, decoded} = NoWayJose.verify(verify_key, token)
      assert decoded["sub"] == "user-1"
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

      assert %NoWayJose.Key{} = rsa_key
      assert rsa_key.kid == "key-1"
      assert rsa_key.alg == :rs256
      assert rsa_key.key_use == "sig"

      assert %NoWayJose.Key{} = ec_key
      assert ec_key.kid == "ec-key-1"
      assert ec_key.alg == :es256
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

      assert {:ok, key} = NoWayJose.Jwks.find_key(keys, "key-1")
      assert key.kid == "key-1"
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

      key = NoWayJose.Jwks.find_key!(keys, "key-1")
      assert key.kid == "key-1"
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
  # Key Store tests
  # ============================================================

  describe "KeyStore" do
    test "put_key/2 and get_key/2", %{rsa_key: key} do
      :ok = NoWayJose.put_key("test-namespace", key)

      assert {:ok, retrieved} = NoWayJose.get_key("test-namespace", "test-rsa")
      assert retrieved.kid == "test-rsa"

      # Cleanup
      NoWayJose.delete_keys("test-namespace")
    end

    test "get_keys/1 returns all keys for namespace", %{rsa_key: key1, ec_key: key2} do
      NoWayJose.put_key("multi-test", key1)
      NoWayJose.put_key("multi-test", key2)

      keys = NoWayJose.get_keys("multi-test")
      assert length(keys) == 2

      # Cleanup
      NoWayJose.delete_keys("multi-test")
    end

    test "delete_keys/1 removes all keys", %{rsa_key: key} do
      NoWayJose.put_key("delete-test", key)
      assert {:ok, _} = NoWayJose.get_key("delete-test", "test-rsa")

      :ok = NoWayJose.delete_keys("delete-test")
      assert :error = NoWayJose.get_key("delete-test", "test-rsa")
    end
  end

  # ============================================================
  # HTTP Client tests
  # ============================================================

  describe "Jwks.HttpClient" do
    @tag :integration
    test "passes connect_options through to Req" do
      opts = [connect_options: [transport_opts: [verify: :verify_none]]]
      assert {:ok, body} = NoWayJose.Jwks.HttpClient.fetch("https://httpbin.org/get", opts)
      assert is_binary(body)
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

  defp sample_jwk_json do
    """
    {
      "kty": "RSA",
      "kid": "key-1",
      "alg": "RS256",
      "use": "sig",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
    """
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
