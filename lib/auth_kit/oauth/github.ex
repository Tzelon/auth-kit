defmodule AuthKit.OAuth.GitHub do
  @moduledoc """
  GitHub OAuth sign-in.

  Only a primary verified address from `/user/emails` is used.
  Any other address returns `{:error, %AuthKit.OAuth.Error{}}`.
  """

  require Logger

  alias AuthKit.OAuth.{Error, HTTP, PKCE}

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
      pkce = PKCE.generate()

      query =
        [scope: @default_scope]
        |> Keyword.merge(Keyword.get(config, :authorization_params, []))
        |> Keyword.merge(
          response_type: "code",
          client_id: client_id,
          redirect_uri: redirect_uri,
          state: state,
          code_challenge: pkce.code_challenge,
          code_challenge_method: pkce.code_challenge_method
        )
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)

      {:ok,
       %{
         url: @authorize_url <> "?" <> URI.encode_query(query),
         session_params: %{
           state: state,
           code_verifier: pkce.code_verifier,
           issued_at: System.system_time(:second)
         }
       }}
    end
  end

  def callback(config, params) do
    with {:ok, session_params} <- fetch_config(config, :session_params),
         :ok <- check_error(params),
         {:ok, verifier} <- PKCE.check(params, session_params),
         {:ok, code} <- fetch_param(params, "code"),
         {:ok, token} <- fetch_token(config, code, verifier),
         {:ok, user} <- fetch_user(config, token) do
      {:ok, %{user: user, token: token}}
    end
  end

  defp check_error(%{"error" => error} = params) do
    {:error,
     Error.exception(message: "GitHub returned an error: #{params["error_description"] || error}")}
  end

  defp check_error(_params), do: :ok

  defp fetch_token(config, code, verifier) do
    with {:ok, client_id} <- fetch_config(config, :client_id),
         {:ok, client_secret} <- fetch_config(config, :client_secret),
         {:ok, redirect_uri} <- fetch_config(config, :redirect_uri) do
      case HTTP.post_form(token_url(config), %{
             grant_type: "authorization_code",
             code: code,
             client_id: client_id,
             client_secret: client_secret,
             redirect_uri: redirect_uri,
             code_verifier: verifier
           }) do
        {:ok, 200, %{"access_token" => access_token} = token}
        when is_binary(access_token) and access_token != "" ->
          {:ok, token}

        {:ok, 200, %{"error" => error} = body} ->
          log_github_failure(200, body)

          {:error,
           Error.exception(
             message: "GitHub returned an error: #{body["error_description"] || error}"
           )}

        {:ok, status, body} ->
          log_github_failure(status, body)
          {:error, Error.exception(message: "Token request failed with status #{status}")}

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
        log_github_failure(status, body)
        {:error, Error.exception(message: "#{label} failed with status #{status}")}

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

  defp log_github_failure(status, body) do
    Logger.error(
      "GitHub request failed status=#{status} error=#{github_field(body, "error")} error_description=#{github_field(body, "error_description")}"
    )
  end

  defp github_field(body, key) when is_map(body), do: body[key]
  defp github_field(_body, _key), do: nil

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
