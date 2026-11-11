defmodule AuthKit.Test.OAuthHTTPStub do
  @moduledoc false

  def install_trust! do
    dir = Path.expand("../../tmp/oauth_stub_tls", __DIR__)
    File.mkdir_p!(dir)

    paths = %{
      dir: dir,
      ca: Path.join(dir, "ca.pem"),
      ca_key: Path.join(dir, "ca.key"),
      cert: Path.join(dir, "server.pem"),
      key: Path.join(dir, "server.key"),
      csr: Path.join(dir, "server.csr")
    }

    unless File.exists?(paths.cert) do
      openssl!([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        paths.ca_key,
        "-out",
        paths.ca,
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=auth-kit-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE"
      ])

      openssl!([
        "req",
        "-newkey",
        "rsa:2048",
        "-keyout",
        paths.key,
        "-out",
        paths.csr,
        "-nodes",
        "-subj",
        "/CN=127.0.0.1",
        "-addext",
        "subjectAltName=IP:127.0.0.1"
      ])

      openssl!([
        "x509",
        "-req",
        "-in",
        paths.csr,
        "-CA",
        paths.ca,
        "-CAkey",
        paths.ca_key,
        "-CAcreateserial",
        "-out",
        paths.cert,
        "-days",
        "1",
        "-copy_extensions",
        "copy"
      ])
    end

    unless :persistent_term.get(:auth_kit_test_ca_loaded, false) do
      bundle = Path.join(dir, "bundle.pem")
      system = File.read!("/etc/ssl/certs/ca-certificates.crt")
      File.write!(bundle, [system, "\n", File.read!(paths.ca)])
      :ok = :public_key.cacerts_load(String.to_charlist(bundle))
      :persistent_term.put(:auth_kit_test_ca_loaded, true)
    end

    paths
  end

  def start(handler) when is_function(handler, 1) do
    %{cert: cert, key: key} = install_trust!()
    parent = self()
    ref = make_ref()

    pid =
      spawn_link(fn ->
        :ssl.start()

        case :ssl.listen(0, listen_options(cert, key)) do
          {:ok, listen} ->
            {:ok, {_ip, port}} = :ssl.sockname(listen)
            send(parent, {ref, {:ok, port}})
            accept(listen, handler)

          {:error, reason} ->
            send(parent, {ref, {:error, reason}})
        end
      end)

    receive do
      {^ref, {:ok, port}} ->
        %{pid: pid, port: port, base: "https://127.0.0.1:#{port}"}

      {^ref, {:error, reason}} ->
        Process.exit(pid, :kill)
        raise "oauth HTTP stub failed to listen: #{inspect(reason)}"
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

  def json(status, body, headers \\ []) do
    payload = JSON.encode!(body)

    header_lines =
      Enum.map(headers, fn {key, value} ->
        [to_string(key), ": ", to_string(value), "\r\n"]
      end)

    [
      "HTTP/1.1 #{status} #{reason(status)}\r\n",
      "content-type: application/json\r\n",
      "content-length: #{byte_size(payload)}\r\n",
      header_lines,
      "connection: close\r\n",
      "\r\n",
      payload
    ]
  end

  defp listen_options(cert, key) do
    [
      :binary,
      packet: :raw,
      active: false,
      reuseaddr: true,
      ip: {127, 0, 0, 1},
      certfile: String.to_charlist(cert),
      keyfile: String.to_charlist(key)
    ]
  end

  defp accept(listen, handler) do
    case :ssl.transport_accept(listen, :infinity) do
      {:ok, socket} ->
        case :ssl.handshake(socket, :infinity) do
          {:ok, socket} ->
            spawn_link(fn -> serve(socket, handler) end)
            accept(listen, handler)

          {:error, _reason} ->
            :ssl.close(socket)
            accept(listen, handler)
        end

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        accept(listen, handler)
    end
  end

  defp serve(socket, handler) do
    request = read_request(socket)
    :ssl.send(socket, handler.(request))
    :ssl.close(socket)
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
      case :ssl.recv(socket, 0, 5_000) do
        {:ok, data} -> read_headers(socket, buffer <> data)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp read_body(_socket, already, length) when byte_size(already) >= length do
    binary_part(already, 0, length)
  end

  defp read_body(socket, already, length) do
    {:ok, data} = :ssl.recv(socket, length - byte_size(already), 5_000)
    read_body(socket, already <> data, length)
  end

  defp openssl!(args) do
    case System.cmd("openssl", args, stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {output, status} -> raise "openssl failed (#{status}): #{output}"
    end
  end

  defp reason(200), do: "OK"
  defp reason(302), do: "Found"
  defp reason(400), do: "Bad Request"
  defp reason(401), do: "Unauthorized"
  defp reason(status), do: Integer.to_string(status)
end
