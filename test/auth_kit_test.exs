defmodule AuthKitTest do
  use ExUnit.Case
  doctest AuthKit

  test "greets the world" do
    assert AuthKit.hello() == :world
  end
end
