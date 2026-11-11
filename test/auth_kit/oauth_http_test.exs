defmodule AuthKit.OAuthHTTPTest do
  use ExUnit.Case, async: false

  alias AuthKit.OAuth.HTTP
  alias AuthKit.Test.OAuthHTTPStub

  test "refuses a non-https url without connecting" do
    assert {:error, %{message: "Refusing non-HTTPS URL"}} =
             HTTP.get_full("http://127.0.0.1:9/certs")

    assert {:error, %{message: "Refusing non-HTTPS URL"}} =
             HTTP.post_form("http://127.0.0.1:9/token", %{"code" => "x"})
  end

  test "returns a redirect instead of following it" do
    stub =
      OAuthHTTPStub.start(fn _request ->
        OAuthHTTPStub.json(302, %{}, [{"location", "https://example.com/away"}])
      end)

    on_exit(fn -> OAuthHTTPStub.stop(stub) end)

    assert {:ok, 302, headers, _body} = HTTP.get_full(stub.base <> "/certs")
    assert headers["location"] == "https://example.com/away"
  end
end
