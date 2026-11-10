defmodule AuthKit.Test.OAuthHTTPStub do
  @moduledoc false

  def start(handler) when is_function(handler, 1) do
    parent = self()
    ref = make_ref()

    pid =
      spawn_link(fn ->
        {:ok, listen} =
          :gen_tcp.listen(0, [
            :binary,
            packet: :raw,
            active: false,
            reuseaddr: true,
            ip: {127, 0, 0, 1}
          ])

        {:ok, port} = :inet.port(listen)
        send(parent, {ref, port})
        accept(listen, handler)
      end)

    receive do
      {^ref, port} -> %{pid: pid, port: port, base: "http://127.0.0.1:#{port}"}
    after
      2_000 ->
        Process.exit(pid, :kill)
        raise "oauth HTTP stub failed to listen"
    end
  end

  def stop(%{pid: pid}) do
    if Process.alive?(pid) do
      Process.unlink(pid)
      Process.exit(pid, :kill)
    end

    :ok
  end

  def json(status, body) do
    payload = JSON.encode!(body)

    [
      "HTTP/1.1 #{status} #{reason(status)}\r\n",
      "content-type: application/json\r\n",
      "content-length: #{byte_size(payload)}\r\n",
      "connection: close\r\n",
      "\r\n",
      payload
    ]
  end

  defp accept(listen, handler) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        spawn_link(fn -> serve(socket, handler) end)
        accept(listen, handler)

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        :ok
    end
  end

  defp serve(socket, handler) do
    request = read_request(socket)
    :gen_tcp.send(socket, handler.(request))
    :gen_tcp.close(socket)
  end

  defp read_request(socket) do
    {:ok, data} = read_headers(socket, "")
    [head, rest] = String.split(data, "\r\n\r\n", parts: 2)
    [request_line | header_lines] = String.split(head, "\r\n")
    [method, target | _] = String.split(request_line, " ")
    path = target |> String.split("?", parts: 2) |> hd()

    headers =
      Map.new(header_lines, fn line ->
        [key, value] = String.split(line, ":", parts: 2)
        {String.downcase(String.trim(key)), String.trim(value)}
      end)

    length = headers |> Map.get("content-length", "0") |> String.to_integer()
    %{method: method, path: path, headers: headers, body: read_body(socket, rest, length)}
  end

  defp read_headers(socket, buffer) do
    if String.contains?(buffer, "\r\n\r\n") do
      {:ok, buffer}
    else
      case :gen_tcp.recv(socket, 0, 5_000) do
        {:ok, data} -> read_headers(socket, buffer <> data)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp read_body(_socket, already, length) when byte_size(already) >= length do
    binary_part(already, 0, length)
  end

  defp read_body(socket, already, length) do
    {:ok, data} = :gen_tcp.recv(socket, length - byte_size(already), 5_000)
    read_body(socket, already <> data, length)
  end

  defp reason(200), do: "OK"
  defp reason(400), do: "Bad Request"
  defp reason(401), do: "Unauthorized"
  defp reason(status), do: Integer.to_string(status)
end
