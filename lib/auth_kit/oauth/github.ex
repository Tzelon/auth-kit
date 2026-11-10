defmodule AuthKit.OAuth.GitHub do
  @moduledoc """
  Only a primary verified address from `/user/emails` is used.
  Any other mailbox returns `{:error, %AuthKit.OAuth.Error{}}`.
  """

  alias AuthKit.OAuth.{Error, HTTP}

  @authorize_url "https://github.com/login/oauth/authorize"
  @token_url "https://github.com/login/oauth/access_token"
  @user_url "https://api.github.com/user"
  @emails_url "https://api.github.com/user/emails"
  @default_scope "read:user user:email"
  @user_agent "auth-kit"

  def authorize_url(config) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      state = random_token()

      query =
        [scope: @default_scope]
        |> Keyword.merge(Keyword.get(config, :authorization_params, []))
        |> Keyword.merge(
          response_type: "code",
          client_id: client_id,
          redirect_uri: redirect_uri,
          state: state
        )
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)

      {:ok,
       %{url: @authorize_url <> "?" <> URI.encode_query(query), session_params: %{state: state}}}
    end
  end

  def callback(config, params) do
    with {:ok, session_params} <- fetch_config(config, :session_params),
         :ok <- check_error(params),
         :ok <- check_state(params, session_params),
         {:ok, code} <- fetch_param(params, "code"),
         {:ok, token} <- fetch_token(config, code),
         {:ok, user} <- fetch_user(config, token) do
      {:ok, %{user: user, token: token}}
    end
  end

  defp check_error(%{"error" => error} = params) do
    {:error,
     Error.exception(message: "GitHub returned an error: #{params["error_description"] || error}")}
  end

  defp check_error(_params), do: :ok

  defp check_state(params, session_params) do
    expected = session_params[:state] || session_params["state"]
    actual = params["state"]

    if is_binary(expected) and is_binary(actual) and byte_size(expected) == byte_size(actual) and
         :crypto.hash_equals(expected, actual) do
      :ok
    else
      {:error, Error.exception(message: "Invalid state param, possible CSRF attempt")}
    end
  end

  defp fetch_token(config, code) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, client_secret} <- fetch_config(config, :client_secret),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      case HTTP.post_form(token_url(config), %{
             grant_type: "authorization_code",
             code: code,
             client_id: client_id,
             client_secret: client_secret,
             redirect_uri: redirect_uri
           }) do
        {:ok, 200, %{"access_token" => access_token} = token}
        when is_binary(access_token) and access_token != "" ->
          {:ok, token}

        {:ok, 200, %{"error" => error} = body} ->
          {:error,
           Error.exception(
             message: "GitHub returned an error: #{body["error_description"] || error}"
           )}

        {:ok, status, body} ->
          {:error,
           Error.exception(
             message: "Token request failed with status #{status}: #{inspect(body)}"
           )}

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp fetch_user(config, %{"access_token" => access_token}) do
    headers = [
      {"authorization", "Bearer " <> access_token},
      {"user-agent", @user_agent}
    ]

    with {:ok, profile} <- get_profile(user_url(config), headers, "GitHub user request"),
         {:ok, emails} <- get_profile(emails_url(config), headers, "GitHub email request"),
         {:ok, email} <- primary_verified_email(emails),
         {:ok, sub} <- subject(profile) do
      {:ok,
       %{
         "sub" => sub,
         "email" => email,
         "email_verified" => true,
         "name" => display_name(profile, email),
         "picture" => profile["avatar_url"]
       }}
    end
  end

  defp get_profile(url, headers, label) do
    case HTTP.get(url, headers) do
      {:ok, 200, body} when is_map(body) or is_list(body) ->
        {:ok, body}

      {:ok, status, body} ->
        {:error,
         Error.exception(message: "#{label} failed with status #{status}: #{inspect(body)}")}

      {:error, error} ->
        {:error, error}
    end
  end

  defp primary_verified_email(emails) when is_list(emails) do
    case Enum.find(emails, &(&1["primary"] == true)) do
      %{"email" => email, "verified" => true} when is_binary(email) and email != "" ->
        {:ok, email}

      %{"primary" => true} ->
        {:error, Error.exception(message: "Email is not verified")}

      _ ->
        {:error, Error.exception(message: "GitHub account has no primary verified email")}
    end
  end

  defp primary_verified_email(_emails) do
    {:error, Error.exception(message: "GitHub account has no primary verified email")}
  end

  defp subject(%{"id" => id}) when is_integer(id), do: {:ok, Integer.to_string(id)}
  defp subject(%{"id" => id}) when is_binary(id) and id != "", do: {:ok, id}

  defp subject(_profile),
    do: {:error, Error.exception(message: "GitHub profile is missing an id")}

  defp display_name(profile, email) do
    [profile["name"], profile["login"], email]
    |> Enum.find(&(is_binary(&1) and String.trim(&1) != ""))
    |> String.trim()
  end

  defp token_url(config), do: config[:token_url] || @token_url
  defp user_url(config), do: config[:user_url] || @user_url
  defp emails_url(config), do: config[:emails_url] || @emails_url

  defp fetch_config(config, key) do
    case Keyword.get(config, key) do
      nil -> {:error, Error.exception(message: "Missing #{inspect(key)} in config")}
      value -> {:ok, value}
    end
  end

  defp fetch_param(params, key) do
    case params[key] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, Error.exception(message: "Missing #{inspect(key)} param")}
    end
  end

  defp random_token do
    32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
  end
end
