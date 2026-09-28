defmodule AuthKit.Auth.HttpError do
  @status_code %{
    ok: 200,
    created: 201,
    accepted: 202,
    no_content: 204,
    multiple_choices: 300,
    moved_permanently: 301,
    found: 302,
    see_other: 303,
    not_modified: 304,
    temporary_redirect: 307,
    bad_request: 400,
    unauthorized: 401,
    payment_required: 402,
    forbidden: 403,
    not_found: 404,
    method_not_allowed: 405,
    not_acceptable: 406,
    proxy_authentication_required: 407,
    request_timeout: 408,
    conflict: 409,
    gone: 410,
    length_required: 411,
    precondition_failed: 412,
    payload_too_large: 413,
    uri_too_long: 414,
    unsupported_media_type: 415,
    range_not_satisfiable: 416,
    expectation_failed: 417,
    misdirected_request: 421,
    unprocessable_entity: 422,
    locked: 423,
    failed_dependency: 424,
    too_early: 425,
    upgrade_required: 426,
    precondition_required: 428,
    too_many_requests: 429,
    request_header_fields_too_large: 431,
    unavailable_for_legal_reasons: 451,
    internal_server_error: 500,
    not_implemented: 501,
    bad_gateway: 502,
    service_unavailable: 503,
    gateway_timeout: 504,
    http_version_not_supported: 505,
    variant_also_negotiates: 506,
    insufficient_storage: 507,
    loop_detected: 508,
    not_extended: 510,
    network_authentication_required: 511
  }

  # Define the exception with default values
  defexception status: :internal_server_error,
               body: nil,
               headers: %{},
               status_code: 500,
               message: "hi",
               plug_status: 500

  # Create a new HttpError  
  def new(status \\ :internal_server_error, body \\ nil, headers \\ %{}, status_code \\ nil) do
    # Calculate status_code based on status
    calculated_status_code =
      cond do
        status_code != nil -> status_code
        is_integer(status) -> status
        true -> Map.get(@status_code, status, 500)
      end

    processed_body =
      case body do
        nil ->
          nil

        %{} = b ->
          # Extract message if it exists
          message = Map.get(b, :message)

          # Generate code from message if present
          code =
            if is_binary(message) do
              message
              |> String.upcase()
              |> String.replace(" ", "_")
              |> String.replace(~r/[^A-Z0-9_]/, "")
            end

          # Add code to body if we generated one
          if code && code != "", do: Map.put(b, :code, code), else: b

        _ ->
          body
      end

    # Create the exception struct
    %__MODULE__{
      status: status,
      body: processed_body,
      headers: headers,
      status_code: calculated_status_code,
      message: processed_body,
      plug_status: calculated_status_code
    }
  end

  # Exception protocol implementation
  def exception(opts) do
    status = Keyword.get(opts, :status, :internal_server_error)
    body = Keyword.get(opts, :body)
    headers = Keyword.get(opts, :headers, %{})
    status_code = Keyword.get(opts, :status_code)

    new(status, body, headers, status_code)
  end

  # Implementation of message function for Exception behavior
  def message(%__MODULE__{body: body}) do
    case body do
      %{message: message} when is_binary(message) -> message
      body when is_binary(body) -> body
      _ -> "API Error"
    end
  end
end
