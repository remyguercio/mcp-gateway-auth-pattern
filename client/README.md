# MCP OAuth Client CLI

A command-line interface for interacting with MCP (Model Context Protocol) servers using OAuth2.1 authentication. This client supports tool discovery, listing, and calling through a streamable HTTP transport.

## Features

- = **OAuth2.1 Authentication**: Full support for authorization code flow with PKCE
- =' **Tool Management**: List and call tools exposed by MCP servers
- =� **Token Persistence**: Automatically stores and refreshes OAuth tokens
- <� **Interactive Mode**: REPL interface for continuous interaction
- =� **Streamable HTTP**: Uses efficient streaming transport (not SSE)
- <� **Rich Terminal UI**: Beautiful output with colors and tables

## Installation

This project uses `uv` for dependency management. Install dependencies with:

```bash
uv sync
```

## Usage

### Quick Start

The easiest way to use the client is to provide a server URL, which starts interactive mode by default:

```bash
uv run mcp-auth-client http://localhost:8001/mcp
```

### Command Line Interface

The client provides several commands for interacting with MCP servers:

```bash
# Start interactive mode (default when only URL is provided)
uv run mcp-auth-client <server-url>

# List all available commands
uv run mcp-auth-client --help

# List tools available on a server
uv run mcp-auth-client list-tools <server-url>

# Call a specific tool
uv run mcp-auth-client call-tool <server-url> <tool-name> --args '{"param": "value"}'

# Start interactive session explicitly
uv run mcp-auth-client interactive <server-url>

# Clear stored authentication
uv run mcp-auth-client clear-auth
```

### Examples

#### List Available Tools

```bash
uv run mcp-auth-client list-tools http://localhost:3000/mcp
```

This will:
1. Initiate OAuth authentication flow (if not already authenticated)
2. Open your browser for authorization
3. Display all available tools in a formatted table

#### Call a Tool

```bash
# Simple tool call without arguments
uv run mcp-auth-client call-tool http://localhost:3000/mcp get_time

# Tool call with arguments
uv run mcp-auth-client call-tool http://localhost:3000/mcp get_weather --args '{"location": "San Francisco"}'
```

#### Interactive Mode

The interactive mode provides a REPL interface for continuous interaction:

```bash
uv run mcp-auth-client interactive http://localhost:3000/mcp
```

Commands in interactive mode:
- `list` - List all available tools
- `call <tool> [args]` - Call a tool with optional JSON arguments
- `help` - Show available commands
- `quit` - Exit the session

Example interactive session:
```
mcp> list
mcp> call get_weather {"location": "London"}
mcp> quit
```

### OAuth Callback Port

By default, the OAuth callback server runs on port 3000. You can change this:

```bash
uv run mcp-auth-client list-tools http://localhost:3000/mcp --port 9090
```

## OAuth Flow

The client implements the full OAuth2.1 authorization code flow:

1. **Discovery**: Fetches OAuth metadata from well-known endpoints
2. **Registration**: Dynamically registers the client if supported
3. **Authorization**: Opens browser for user authorization
4. **Token Exchange**: Exchanges authorization code for access tokens
5. **Token Storage**: Persists tokens securely for future use
6. **Token Refresh**: Automatically refreshes expired tokens

## Token Storage

OAuth tokens and client information are stored in:
- **Linux/macOS**: `~/.config/mcp-oauth-client/`
- **Custom location**: Set `XDG_CONFIG_HOME` environment variable

Files are stored with restrictive permissions (0600) for security.

## Server Requirements

The MCP server must:
- Support streamable HTTP transport
- Implement OAuth2.1 authentication (optional but required for this client)
- Expose the `/mcp` endpoint for streamable HTTP
- Support protected resource metadata discovery (recommended)

## Troubleshooting

### Connection Issues

If you can't connect to a server:
1. Verify the server URL includes the `/mcp` path
2. Check that the server supports streamable HTTP
3. Ensure the OAuth callback port is not in use

### Authentication Issues

If authentication fails:
1. Clear stored tokens: `uv run mcp-auth-client clear-auth`
2. Try a different callback port with `--port`
3. Check browser console for authorization errors

### Tool Execution Issues

If tool calls fail:
1. Verify the tool name with `list-tools`
2. Check required parameters in the tool description
3. Ensure JSON arguments are properly formatted

## Development

The client is built with:
- **MCP Python SDK**: Official Python SDK for Model Context Protocol
- **Click**: Command-line interface creation
- **Rich**: Terminal formatting and colors
- **httpx**: Async HTTP client with OAuth support
- **Authlib**: OAuth2 implementation helpers

## Security Considerations

- Tokens are stored locally with restricted file permissions
- PKCE is used for all authorization flows
- Tokens are automatically refreshed when expired
- No credentials are logged or displayed
- Browser-based authorization ensures secure credential entry

## License

This project is part of the MCP examples and follows the same license as the parent repository.