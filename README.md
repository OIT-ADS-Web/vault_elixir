# VaultElixir

## Usage

  In config/runtime.exs, Place a call to VaultElixir.vault() to call vault and load environment variables in the VaultElixir module.

  In config/runtime.exs, use VaultElixir.ensure_vars_set([ LIST of ENVIRONMENT VARIABLES from Vault ]) to ensure that vault
    was configured for the application correctly.
   
  Move config blocks from config/config.exs (or dev.exs or prod.exs) into config/runtime.exs, but change the calls to System.get_env() to VaultElixir.get_env().  This ensures that variables set by vault are found or, if SKIP_VAULT=true is set that the environment variables from the .env file are found in local development mode.
  
## Installation

The package can be installed by adding `vault_elixir` to your list of dependencies in `mix.exs`:

NOTE: Rather than using 'branch:' below, use 'tag:' and pick the latest tagged version to prevent
potential issues with interface changes. See 'mix help deps' for more information.

```elixir
def deps do
  [
    {:vault_elixir, git: "https://github.com/OIT-ADS-Web/vault_elixir", tag: "vN.N.N"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/vault_elixir>.

