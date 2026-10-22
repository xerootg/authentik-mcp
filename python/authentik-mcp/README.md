# Authentik MCP Server

A Model Context Protocol (MCP) server that provides comprehensive integration with Authentik's API for user management, authentication flows, and system administration.

## Features

### User Management
- Create, read, update, and delete users
- Manage user groups and permissions
- User search and filtering capabilities

### Group Management
- Create and manage user groups
- Assign users to groups
- Group hierarchy management

### Application Management
- Manage Authentik applications
- Configure application providers
- Application deployment and configuration

### Provider Management
- Create, update, and delete providers of any type (oauth2, proxy, ldap, saml, radius, scim, rac, ssf, google_workspace, microsoft_entra)
- Type-aware editing via authentik's per-type endpoints

### Outpost Management
- Create, update, and delete outposts
- Control which providers an outpost serves
- Inspect outpost health and available service connections

### Authentication Flows
- View and manage authentication flows
- Flow configuration and customization
- Flow monitoring and diagnostics

### Stages, Policies and Brands
- Create, inspect, update and delete stages of every type
- Bind stages into flows, reorder them, and gate them with policies
- Manage policies and policy bindings
- Set each brand's default flows (authentication, recovery, user settings, ...)

### Event Monitoring
- System event tracking and audit logs
- Real-time event monitoring
- Event filtering and search capabilities

### System Administration
- API token management  
- Provider configuration
- System health monitoring
- Configuration management

## MCP Integration

This server is designed to be used with MCP-compatible tools and platforms. It provides a standardized interface for interacting with Authentik instances through the Model Context Protocol.

### Configuration

The server needs the following to connect. Each may be passed as a `serve` flag,
set via an environment variable, or stored once via `authentik-mcp login` (see
[Setup & maintenance](#setup--maintenance-login--rotate--logout--status)):
- `base-url`: Base URL of your Authentik instance
- `token`: Authentik API token (`intent=api`)
- `verify-ssl`: Enable/disable SSL certificate verification (optional, default: true)

Resolution order for `serve` is: CLI flag → environment variable → stored
credential file. If none provide a base URL and token, the server exits with a
hint to run `authentik-mcp login`.

### Environment Variables
You can also configure the server using environment variables:
- `AUTHENTIK_BASE_URL`: Base URL of your Authentik instance
- `AUTHENTIK_TOKEN`: Authentik API token
- `AUTHENTIK_VERIFY_SSL`: SSL certificate verification (true/false)

## Setup & maintenance (`login` / `rotate` / `logout` / `status`)

The package ships a small CLI for obtaining and maintaining the API token, so
you don't have to keep a token inline in your MCP client config. Credentials are
stored at `$XDG_CONFIG_HOME/authentik-mcp/config.json` (mode `0600`), and the
default `serve` command reads them from there (CLI flags and
`AUTHENTIK_BASE_URL`/`AUTHENTIK_TOKEN` still take precedence).

```bash
# Mint a durable intent=api token and store it (+ register in Claude Code).
# Default method execs into the Authentik server pod via your (ak-backed)
# kubeconfig — base URL and username are auto-detected from the ak CLI profile.
authentik-mcp login

# No cluster access? store a token you created in the UI instead:
authentik-mcp login --method manual            # prompts, or --token <key>

# Rotate: mint a fresh token and revoke the previous one.
authentik-mcp rotate

# Inspect what's stored and check it against the API.
authentik-mcp status

# Revoke + remove the stored credential and the Claude entry.
authentik-mcp logout --revoke
```

`login`/`rotate` register an `authentik` server in your Claude Code **user**
config as `authentik-mcp serve` (no inline token — the credential stays only in
the `0600` file). Pass `--no-claude` to skip that.

Useful flags for the kube method: `--namespace` (default `authentik`),
`--pod-selector` (default `authentik-server`), `--username`, `--identifier`
(default `claude-code-mcp`), `--base-url`.

### Creating the token manually

If you'd rather create the token yourself: log in to Authentik as an admin →
**Directory → Tokens → Create** → set Intent to **API** → copy the key and feed
it via `authentik-mcp login --method manual`, the `--token` flag, or
`AUTHENTIK_TOKEN`.

## Available Tools

### User Management
- `authentik_list_users` - List all users with filtering options
- `authentik_get_user` - Get detailed user information
- `authentik_create_user` - Create new users
- `authentik_update_user` - Update existing users
- `authentik_delete_user` - Delete users

### Group Management
- `authentik_list_groups` - List all groups
- `authentik_get_group` - Get group details
- `authentik_create_group` - Create new groups
- `authentik_update_group` - Update existing groups
- `authentik_delete_group` - Delete groups

### Application Management
- `authentik_list_applications` - List all applications
- `authentik_get_application` - Get application details
- `authentik_create_application` - Create new applications
- `authentik_update_application` - Update existing applications
- `authentik_delete_application` - Delete applications

### Event Monitoring
- `authentik_list_events` - List system events and audit logs
- `authentik_get_event` - Get detailed event information

### Flow Management
- `authentik_list_flows` - List authentication flows
- `authentik_get_flow` - Get flow details
- `authentik_update_flow` - Update a flow (PATCH)
- `authentik_list_flow_bindings` - List the stages bound to a flow (`target` = flow pk), in order
- `authentik_create_flow_binding` - Bind a stage into a flow
- `authentik_update_flow_binding` - Change a binding's order or policy evaluation
- `authentik_delete_flow_binding` - Remove a stage from a flow (the stage is kept)

### Stage Management
- `authentik_list_stages` - List stages of every type
- `authentik_get_stage` - Get a stage's full config (type looked up automatically)
- `authentik_create_stage` - Create a stage; `stage_type` is the API path, e.g. `identification`, `authenticator/validate`, `prompt/stages`
- `authentik_update_stage` - Update a stage (PATCH)
- `authentik_delete_stage` - Delete a stage
- `authentik_list_prompts` - List prompt fields used by prompt stages

### Policy Management
- `authentik_list_policies` - List policies of every type
- `authentik_get_policy` - Get a policy's full config (type looked up automatically)
- `authentik_create_policy` - Create a policy (`policy_type` e.g. `expression`, `password`)
- `authentik_update_policy` - Update a policy (PATCH)
- `authentik_list_policy_bindings` - List policy bindings (`target` = the bound object's `policybindingmodel_ptr_id`)
- `authentik_create_policy_binding` / `authentik_update_policy_binding` / `authentik_delete_policy_binding`

### Brand Management
- `authentik_list_brands` - List brands and their default flows
- `authentik_update_brand` - Update a brand (PATCH), e.g. set `flow_recovery`

### System
- `authentik_get_system_info` - authentik version

### Provider Management
- `authentik_list_providers` - List all providers (polymorphic, read-only `/providers/all/`)
- `authentik_get_provider` - Get provider details; pass `provider_type` for full type-specific fields
- `authentik_create_provider` - Create a provider of a given type (`provider_type` + `data`)
- `authentik_update_provider` - Update a provider (`provider_type`, `provider_id`, `data`)
- `authentik_delete_provider` - Delete a provider (`provider_type`, `provider_id`)

  Supported `provider_type` values: `oauth2`, `proxy`, `ldap`, `saml`, `radius`, `scim`, `rac`, `ssf`, `google_workspace`, `microsoft_entra`. Providers are created/updated through authentik's type-specific endpoints, so the `data` object carries the type's fields (e.g. `name`, `authorization_flow`, `invalidation_flow`, plus type-specific ones). Read an existing provider with `provider_type` set to learn the exact shape.

### Outpost Management
- `authentik_list_outposts` - List outposts
- `authentik_get_outpost` - Get outpost details
- `authentik_create_outpost` - Create an outpost; `providers` is the list of provider IDs it serves
- `authentik_update_outpost` - Update an outpost (change `providers` to retarget which providers it serves)
- `authentik_delete_outpost` - Delete an outpost
- `authentik_get_outpost_health` - Get health/status of an outpost's instances
- `authentik_list_outpost_service_connections` - List Docker/Kubernetes service connections for deploying outposts

### Token Management
- `authentik_list_tokens` - List API tokens
- `authentik_create_token` - Create new API tokens

## Resources

The server provides access to the following resources:
- `authentik://users` - User management
- `authentik://groups` - Group management
- `authentik://applications` - Application management
- `authentik://events` - Event monitoring and audit logs
- `authentik://flows` - Authentication flows
- `authentik://providers` - Authentication providers
- `authentik://outposts` - Outposts and the providers they serve
- `authentik://stages` - Flow stages of every type

## Example Usage

```python
# List all users
users = await authentik_list_users()

# Create a new user
new_user = await authentik_create_user({
    "username": "johndoe",
    "email": "john@example.com",
    "name": "John Doe",
    "password": "secure-password"
})

# Get recent events
events = await authentik_list_events({
    "ordering": "-created",
    "page_size": 10
})

# Create a new group
group = await authentik_create_group({
    "name": "Developers",
    "is_superuser": False
})
```

## Security Considerations

- Always use HTTPS in production environments
- Rotate API tokens regularly
- Use least-privilege principle when creating tokens
- Monitor API usage through Authentik's audit logs
- Consider using separate tokens for different environments

## Development

### Local Development
## MCP Integration & Usage

This server is designed to be managed by MCP-compatible tools and platforms. It provides a standardized interface for interacting with Authentik instances through the Model Context Protocol.

### Example Configurations

**VS Code / GitHub Copilot Workspace (settings.json):**
```jsonc
"mcp": {
  "servers": {
    "authentik": {
      "command": "uvx",
      "args": [
        "authentik-mcp",
        "--base-url", "https://your-authentik-instance",
        "--token", "your-api-token"
      ]
    }
  }
}
```

**Claude Desktop (claude_desktop_config.json):**
```json
{
  "mcpServers": {
    "authentik": {
      "command": "uvx",
      "args": [
        "authentik-mcp",
        "--base-url",
        "https://your-authentik-instance",
        "--token",
        "your-api-token"
      ]
    }
  }
}
```

### Integration Notes
- Use `uvx authentik-mcp` for Python versions as shown above
- For Node.js versions, use `npx @cdmx/authentik-mcp` if you are using the Node.js implementation
- Let your MCP tool manage the environment and server lifecycle
- Direct CLI usage is not recommended for most users

## Requirements

- Python 3.10 or higher
- Valid Authentik API token with appropriate permissions

## License

MIT License - see LICENSE file for details.

## Support

- [Authentik Documentation](https://docs.goauthentik.io/)
- [GitHub Issues](https://github.com/goauthentik/authentik-mcp/issues)
- [Authentik Community](https://github.com/goauthentik/authentik/discussions)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.