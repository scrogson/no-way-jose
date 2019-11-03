defmodule NoWayJoseTest do
  use ExUnit.Case
  doctest NoWayJose

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

    signer = NoWayJose.generate_rsa(4096, :der)

    assert {:ok, token} = NoWayJose.sign(claims, signer)

    {header, payload} = peek(token)

    assert %{"typ" => "JWT", "alg" => "RS512"} = Jason.decode!(header)
    assert ^claims = Jason.decode!(payload)
  end

  defp peek(token) do
    [header, payload, _signature] = String.split(token, ".")

    header = Base.url_decode64!(header, padding: false)
    payload = Base.url_decode64!(payload, padding: false)

    {header, payload}
  end
end
