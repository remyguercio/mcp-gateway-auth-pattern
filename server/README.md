# MCP OAuth 2.1 Authenticated Server

A Model Context Protocol (MCP) server implementation with OAuth 2.1 authentication support. This server provides two protected tools that require valid OAuth Bearer tokens.

## Features

- **OAuth 2.1 compliant authentication** using RFC 7662 token introspection
- **Two authenticated tools**:
  - `multiply`: Multiplies two numbers
  - `oauth_details`: Returns OAuth client authentication information
- **Streamable HTTP transport** for MCP communication
- **Security features**: SSRF protection, token validation, audience verification
- **Standards compliant**: Implements MCP Authorization Spec and OAuth RFCs

## Requirements

- Python 3.10+
- UV package manager
- OAuth 2.1 authorization server with token introspection support

## Installation

```bash
# Install dependencies with UV
uv sync

# Install in development mode
uv pip install -e .
```

## Usage

### Starting the Server

```bash
# Basic usage
uv run mcp-auth-server --auth-server-url http://localhost:9000

# With custom host/port
uv run mcp-auth-server \
  --auth-server-url http://localhost:9000 \
  --host 0.0.0.0 \
  --port 8080

# With debug mode and custom scopes
uv run mcp-auth-server \
  --auth-server-url http://localhost:9000 \
  --debug \
  --required-scopes "openid,profile"
```

### Command Line Options

- `--auth-server-url` (required): OAuth 2.1 authorization server base URL
- `--host`: Server host address (default: localhost)
- `--port`: Server port number (default: 8001)
- `--debug`: Enable debug mode with verbose logging
- `--required-scopes`: Comma-separated list of required OAuth scopes (default: openid)

### OAuth Discovery

The server provides OAuth Protected Resource Metadata at:
```
GET /.well-known/oauth-protected-resource
```

## Authentication

All tools require a valid OAuth 2.1 Bearer token in the Authorization header:

```
Authorization: Bearer <your-access-token>
```

The server validates tokens using OAuth 2.0 Token Introspection (RFC 7662) against the configured authorization server.

## Available Tools

### multiply

Multiplies two numbers and returns the result with authentication context.

**Parameters:**
- `a` (float): First number
- `b` (float): Second number

**Returns:**
```json
{
  "operation": "multiplication",
  "inputs": {"a": 5.0, "b": 3.0},
  "result": 15.0,
  "authenticated_as": "client-id",
  "scopes": ["openid"]
}
```

### oauth_details

Returns OAuth authentication details for the current client.

**Returns:**
```json
{
  "authenticated": true,
  "client_id": "your-client-id",
  "scopes": ["openid", "profile"],
  "subject": "user123",
  "issuer": "http://localhost:9000",
  "resource": "http://localhost:8001",
  "expires_at": 1234567890,
  "token_type": "Bearer"
}
```

## Development

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=mcp_auth_server

# Run specific test file
uv run pytest tests/test_server.py
```

### Code Quality

```bash
# Format code
uv run ruff format

# Lint code
uv run ruff check

# Type checking
uv run mypy src/
```

## Security Considerations

- **HTTPS Required**: Production deployments should use HTTPS for all OAuth endpoints
- **SSRF Protection**: Introspection endpoint URLs are validated to prevent SSRF attacks
- **Token Validation**: Tokens are validated for expiry, audience, and required scopes
- **Resource Indicators**: RFC 8707 resource validation ensures tokens are intended for this server

## Standards Compliance

This implementation follows:

- [Model Context Protocol Authorization Specification](http://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [RFC 6749: OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7662: OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/rfc8707)

## License

This project is part of the Tailscale MCP authentication experiment.