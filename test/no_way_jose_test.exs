defmodule NoWayJoseTest do
  use ExUnit.Case
  doctest NoWayJose

  setup do
    on_exit(fn ->
      File.rm("RS512.pem")
      File.rm("RS512.pem.pub")
      File.rm("RS512.der")
    end)
  end

  test "sign" do
    claims = %{
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
    }

    signer = generate_rsa512()
    assert {:ok, jwt} = NoWayJose.sign(claims, signer)

    [header, payload, _signature] = String.split(jwt, ".")

    header = Base.url_decode64!(header, padding: false)
    payload = Base.url_decode64!(payload, padding: false)

    assert %{"typ" => "JWT", "alg" => "RS512"} = Jason.decode!(header)
    assert ^claims = Jason.decode!(payload)
  end

  # This is terrible but it works.
  defp generate_rsa512 do
    System.cmd("ssh-keygen", ~w(-m PEM -t rsa -b 4096 -f RS512.pem))
    # Empty passphrase
    IO.write("\n")
    # Empty confirm passphrase
    IO.write("\n")
    System.cmd("openssl", ~w(rsa -in RS512.pem -outform DER -out RS512.der))
    File.read!("RS512.der")
  end
end
