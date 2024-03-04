
defmodule VaultElixir do
  @moduledoc """
  Vault support for elixir.
  """

  require Logger;
  defstruct [
    connection_options: [],
    use_namespace_token_success: false,
    use_approle_token_success: false,
    use_developer_token_success: false,
    skip_vault: false,
    prefix_secrets: false,
    provider_url: nil,
    vault_secret_paths: nil,
    vault_token: nil, # when supplied by input environment
    vault_login_token: nil, # when supplied by vault login via role/secret, okd jwt login or copied from vault_token
    vault_role_id: nil,
    vault_secret_id: nil,
    vault_namespace_token_path: nil,
    vault_namespace_token: nil,
    vault_fitz_endpoint: nil,
    vault_okd_role: nil,
    vault_auth_token_uri: nil,
    output_pairs: []
  ]

  def skip_vault?() do
    skip = String.downcase(System.get_env("SKIP_VAULT", "false"))
    (skip == "true" || skip == "1" || skip == "yes")
  end

  @doc"""
  The application may call this function after Vault.vault() to ensure that all needed variables
  are loaded. If SKIP_VAULT is set, then the variables should've been set by the
  invoking environment e.g. an O/S script.
  If one or more variables are missing from the environment, an exception will be thrown.
  """
  def ensure_vars_set(var_list) do
    info_msg("Ensure variables set: #{inspect(var_list)}")
    status = Enum.reduce(
      var_list,
      [],
      fn k, acc ->
        v = System.get_env(k)
        if v == nil do
          error_msg("value for: #{k} not found in environment")
          [{:error, k} | acc]
        else
          acc
        end
      end)
    #info_msg("status: #{inspect(status)}")
    if length(status) == 0 do
      info_msg("All required variables were found in the environment")
    else
      throw("vault.ensure_vars_set('#{inspect var_list}' failed to find all the required variables")
    end
  end

  @doc"""

  Vault.vault() load variables from vault and perform vault lookups and put the
    results into env variable before the application starts making the values
    available to the application's configuration
    through System.get_env().

    NOTE: In most cases, it makes sense to call Vault.vault()
      from runtime.exs and then call Vault.ensure_vars_set( list of expected env var names )

    If the SKIP_VAULT environment variable is set to true, yes, or 1 value, vault() does nothing.

    If SKIP_VAULT is false then vault():
      1. loads the REQUIRED env value of VAULT_SECRET_PATH to get the semi-colon separated names
        of the paths of vault secrets to load.  By default, the last part of the path is use
        as part of the resulting name placed into the environment for each secret component.
        Each secret component should be a single name value pair (only 1 level of depth allowed).
        Specifically, the JSON at the VAULT_SECRET_PATH in VAULT should be a simple name-value
        pair JSON. NOTE that it's possible to have the value be a JSON, but the application
        would be responsible for parsing the vault into sub-components.
      2. loads the REQUIRED env value of VAULT_PROVIDER_URL to get the vault https address.
      3. loads the OPTIONAL env values for VAULT_NAMESPACE_TOKEN_PATH, VAULT_FITZ_ENDPOINT,
          and VAULT_OKD_ROLE -- these values are required for OKD vault token login
      4. loads OPTIONAL VAULT_ROLE_ID and VAULT_SECRET_ID env values -- these values
          are required for vault role_id/secret_id login
      5. loads optional VAULT_TOKEN used for development environment vault login

      Missing REQUIRED values will cause an exception preventing the application from running if
        SKIP_VAULT is not specified.
        If SKIP_VAULT is specified, the application environment itself could be used to
          propagate values for vault secrets e.g. using a development .env for startup.

      6. OKD Vault token login is attempted using VAULT_NAMESPACE_TOKEN_PATH, VAULT_FITZ_ENDPOINT
         If successful processing continues at step 10.
      7. OKD Role_id/secret_id login is attempted using VAULT_SECRET_ID and VAULT_ROLE_ID
         If successful processing continues at step 10.
      8. VAULT_TOKEN login is attempted.
         If successful processing continues at step 10.
      9. Since/If no login methods were successful, an exception is raised and program execution stops.
     10. At this point, some form of vault login was successful, so vault values for
          EACH of the VAULT_SECRET_PATH requested are read.
          For each path component, the secrets are read (key, values from vault), and
            for each key in the secret an environment variable is created with a key
            composed of the last component of the path and the key of the vault
            data.
            For instance, a vault secret path of:
              /app/APPNAME/acceptance/postgres
              With a JSON secret like:
                {"database": "dbname", "password": "dbpw"}
              Will generate environment variables like:
                POSTGRES_DATABASE="dbname" and
                POSTGRES_PASSWORD="dbpw"
      11. At this point, if no exceptions occurred, normal elixir application startup continues.


  """
  # Connection options are options appropriate for httpoison
  #    e.g. https://hexdocs.pm/httpoison/readme.html#options
def vault(connection_options \\ []) do

    if !skip_vault?() do
      {:ok, _} = Application.ensure_all_started(:hackney)
      vault_data = struct(__MODULE__)
      vault_data = load_required_env(vault_data)
        |> Map.put(:connection_options, connection_options)

      debug_msg("%Vault{} is #{inspect(vault_data)}")
      rv = use_namespace_token({false, vault_data})
        |> use_approle_token()
        |> use_developer_token()
      vault_msg(rv)
    else
      info_msg("Skipping vault. SKIP_VAULT is set.")
      {false, nil}
    end
  end

  def get_env() do
    System.get_env()
  end

  def get_env(env_name) do
    System.get_env(env_name)
  end

  def vault_msg({successful?, vault_data}) do
    if successful? do
      error_msg("No vault() load errors.")
    else
      error_msg("No vault approach was successful (namespace token, approle token or developer token)")
    end
    {successful?, vault_data}
  end



  def load_required_env(vault_data) do
    secret_path = System.get_env("VAULT_SECRET_PATH")
    info_msg("vault secret path(s) input: #{inspect(secret_path)}")
    if str_empty?(secret_path), do: throw("Vault() requires environment variable VAULT_SECRET_PATH")
    secret_paths = String.split(secret_path, [";",","])
    if length(secret_paths) < 1, do: throw("Vault() requires environment variable VAULT_SECRET_PATH")
    ## info_msg("vault secret paths: #{inspect(secret_paths)}")

    vault_data = vault_data
      |> Map.put(:provider_url, (System.get_env("VAULT_PROVIDER_URL") || throw "Vault() requires environment variable VAULT_PROVIDER_URL"))
      |> Map.put(:vault_token, System.get_env("VAULT_TOKEN")) # optional
      |> Map.put(:vault_role_id, System.get_env("VAULT_ROLE_ID")) # optional
      |> Map.put(:vault_secret_id, System.get_env("VAULT_SECRET_ID")) # optional
      |> Map.put(:vault_fitz_endpoint, System.get_env("VAULT_FITZ_ENDPOINT")) # optional
      |> Map.put(:vault_okd_role, System.get_env("VAULT_OKD_ROLE")) # optional
      |> Map.put(:vault_namespace_token_path, System.get_env("VAULT_NAMESPACE_TOKEN_PATH")) # optional
      |> Map.put(:vault_secret_paths, secret_paths) # required, checked above

    vault_data
  end

  defp get_namespace_token(vault_data) do
    path = vault_data.vault_namespace_token_path
    token = if path != nil, do: File.read!(path), else: nil
    info_msg("vault_namespace_token length is: #{strlen(token)}")
    Map.put(vault_data, :vault_namespace_token, token)
  end

  def use_namespace_token({prior_success?, vault_data}) do
    if prior_success? == false do
      info_msg("Checking OKD namespace token")
      vault_data = get_namespace_token(vault_data)
      {rv, vault_data} = fetch_secrets(:okd_role, vault_data)
      success? = (rv == :ok)
      info_msg("OKD namespace token method #{if success? == false, do: "not "}successful")
      {success?, Map.put(vault_data, :use_namespace_token_success, success?)}
    else
      info_msg("NOT Checking OKD namespace token -- higher priority method was successful")
      {prior_success?, Map.put(vault_data, :use_namespace_token_success, false)}
    end
  end

  def use_approle_token({prior_success?, vault_data}) do
    if prior_success? == false do
      info_msg("Checking approle token")
      success? = false
      {rv, vault_data} = fetch_secrets(:role_secret, vault_data)
      success? = (rv == :ok)
      info_msg("vault approle (role_id/secret_id) token method #{if success? == false, do: "not "}successful")
      {success?, Map.put(vault_data, :use_approle_token_success, success?)}
    else
      info_msg("NOT checking vault approle (role_id/secret_id) token -- higher priority method was successful")
      {prior_success?, Map.put(vault_data, :use_approle_token_success, false)}
    end
  end

  def use_developer_token({prior_success?, vault_data}) do
    if prior_success? == false do
      info_msg("Checking developer token")
      {rv, vault_data} = if vault_data.vault_token != nil do
        fetch_secrets(:dev_token, vault_data)
      else
        success? = false
        info_msg("developer token method #{if success? == false, do: "not "}successful - VAULT_TOKEN not set")
        {success?, Map.put(vault_data, :use_developer_token_success, success?)}
        end
    else
      info_msg("NOT checking developer token -- higher priority method was successful")
      {prior_success?, Map.put(vault_data, :use_developer_token_success, false)}
    end
  end

  def decode_okd_role_secret_token({:ok, data}) do
    data.auth.client_token
  end

  def decode_okd_role_secret_token({:error, err}) do
    error_msg("error decoding okd role login response: #{inspect err}")
    nil
  end

  def vault_login(:okd_role, vault_data) do
    if (!str_empty?(vault_data.vault_fitz_endpoint) and !str_empty?(vault_data.vault_okd_role)) do
      login_url = vault_data.provider_url <> "/v1/auth/global/" <> vault_data.vault_fitz_endpoint <> "/login"
      role_jwt = %{
        jwt: vault_data.vault_namespace_token,
        role: vault_data.vault_okd_role
      }
      payload = Jason.encode!(role_jwt)
      rv = post_request(login_url, payload, [{"content-type", "application/json"}], vault_data.connection_options)
      case rv do
        {:ok, body} ->
          info_msg("okd role login success")
          token = decode_okd_role_secret_token(Jason.decode(body, keys: :atoms))
          if token != nil,
            do:
              {:ok, Map.put(vault_data, :vault_login_token, token)},
            else:
              {:error, vault_data}
        {:error, reason} ->
          error_msg("okd role login approach failure. Reason: #{inspect reason}")
          {:error, vault_data}
      end
    else
      {:error, vault_data}
    end
  end

  def decode_role_secret_token({:ok, data}) do
    data.auth.client_token
  end

  def decode_role_secret_token({:error, err}) do
    error_msg("error decoding role_id/secret_id login response: #{inspect err}")
    nil
  end

  def vault_login(:role_secret, vault_data) do
    if (!str_empty?(vault_data.vault_role_id) and !str_empty?(vault_data.vault_secret_id)) do
      login_url = vault_data.provider_url <> "/v1/auth/ess-web/approle/login"
      role_secret = %{
        role_id: vault_data.vault_role_id,
        secret_id: vault_data.vault_secret_id
      }
      payload = Jason.encode!(role_secret)
      rv = post_request(login_url, payload, [{"content-type", "application/json"}], vault_data.connection_options)
      case rv do
        {:ok, body} ->
          token = decode_role_secret_token(Jason.decode(body, keys: :atoms))
          if token != nil,
            do:
              {:ok, Map.put(vault_data, :vault_login_token, token)},
            else:
              {:error, vault_data}
        {:error, reason} ->
          error_msg("role_id/secret_id login approach failure. Reason: #{inspect reason}")
          {:error, vault_data}
      end
    else
      error_msg("role_id/secret_id login appoach - requires VAULT_ROLE_ID and VAULT_SECRET_ID")
      {:error, vault_data}
    end
  end

  def vault_login(:dev_token, vault_data) do
    # dev token is already logged in unless it's nil, expired or fake, but that's caught by fetch_secrets
    #  for dev, copy vault_token from input env into login token
    {:ok, Map.put(vault_data, :vault_login_token, vault_data.vault_token)}
  end

  def translate_token_method(token_method) do
    case token_method do
      :okd_role -> "okd_role_method"
      :role_secret -> "role_secret_method"
      :dev_token -> "developer_token_method"
    end
  end

  def parse_secret({:ok, vault_resp}, secret_path) do
    hlq = Enum.take(String.split(secret_path, "/"), -1)
    {:ok,
      Enum.reduce(
        Jason.decode!(vault_resp, keys: :atoms).data.data,
        %{},
        fn {k, v}, acc ->
          key = String.upcase("#{hlq}_#{to_string(k)}")
          Map.put(
            acc,
            key,
            to_string(v)
          )
      end)
    }
  end

  def parse_secret({:error, reason}, secret_path) do
    error_msg("Error obtaining secret: #{secret_path} - reason: #{inspect reason}")
    {:error, []}
  end

  def fetch_secrets(token_method, vault_data) do
    {rv, vault_data} = vault_login(token_method, vault_data)
    if rv == :ok do
      auth = get_auth_token_header(vault_data)
      secrets = Enum.reduce(vault_data.vault_secret_paths, %{}, fn sp,acc ->
        info_msg("processing secret path: #{sp}")
        {rv, secret} = get_request(
            "#{vault_data.provider_url}/v1/#{sp}",
            auth,
            vault_data.connection_options
          )
          |> parse_secret(sp)
        #info_msg("secret: #{inspect secret}")
        case rv do
          :ok -> Map.merge(acc, secret)
          :error ->
            error_msg("get secrets failed for secret path: #{sp}")
            acc
        end
      end)
      #debug_msg("secrets: #{inspect(secrets)}")
      System.put_env(secrets)
      {:ok, Map.put(vault_data, :output_pairs, secrets)}
    else
      error_msg("Vault login failed for #{translate_token_method(token_method)}")
      {rv, vault_data}
    end
  end

  defp strlen(s) do
    if str_empty?(s), do: 0, else: String.length(s)
  end

  defp str_empty?(s) do
    (s == nil || String.length(s) == 0)
  end
  @doc """
  Issues a HTTPoison POST request to the given url.

  Returns `{:ok, body}` if the request is successful, `{:error, reason}`
  otherwise.
  """
  def post_request(endpoint_url, payload \\ "", headers \\ [], options \\ []) do
    HTTPoison.post(endpoint_url, payload, headers, options)
    |> case do
      {:ok, %{status_code: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status_code: status_code}} ->
        {:error, status_code}

      {:error, error} ->
        {:error, error.reason}

      v ->
        {:error, v}
    end
  end

  @doc """
  Issues a HTTPoison GET request to the given url.

  Returns `{:ok, body}` if the request is successful, `{:error, reason}`
  otherwise.
  """
  def get_request(endpoint_url, headers \\ [], options \\ []) do
    HTTPoison.get(endpoint_url, headers, options)
    |> case do
      {:ok, %{status_code: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status_code: status_code}} ->
        {:error, status_code}

      {:error, error} ->
        {:error, error.reason}

      v ->
        {:error, v}
    end
  end

  # generate header with token
  defp get_login_resp_token_header(data) do
    [{"X-Vault-Token", Map.get(data["auth"], "client_token")}]
  end

  defp get_auth_token_header(vault_data) do
    if vault_data.vault_login_token == nil do
      error_msg("get_auth_token_header: vault_login_token is nil - login will fail.")
    end
    [{"X-Vault-Token", vault_data.vault_login_token}]
  end

  def error_msg(msg) do
    Logger.error("Vault: #{msg}")
  end

  def info_msg(msg) do
    Logger.info("Vault: #{msg}")
  end

  def debug_msg(msg) do
    #Logger.debug("Vault: #{msg}")
  end

end
