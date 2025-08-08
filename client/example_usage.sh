#!/bin/bash
# Example usage of the MCP OAuth Client CLI

echo "MCP OAuth Client CLI Examples"
echo "============================="
echo ""

# Example server URL (change this to your actual MCP server)
SERVER_URL="http://localhost:8001/mcp"

echo "1. Quick start (interactive mode):"
echo "   uv run mcp-auth-client $SERVER_URL"
echo ""

echo "2. List available tools:"
echo "   uv run mcp-auth-client list-tools $SERVER_URL"
echo ""

echo "3. Call a tool without arguments:"
echo "   uv run mcp-auth-client call-tool $SERVER_URL get_time"
echo ""

echo "4. Call a tool with arguments:"
echo '   uv run mcp-auth-client call-tool $SERVER_URL get_weather --args '"'"'{"location": "San Francisco"}'"'"
echo ""

echo "5. Start interactive session explicitly:"
echo "   uv run mcp-auth-client interactive $SERVER_URL"
echo ""

echo "6. Clear stored authentication:"
echo "   uv run mcp-auth-client clear-auth"
echo ""

echo "7. Use custom OAuth callback port (default is 3000):"
echo "   uv run mcp-auth-client $SERVER_URL --port 9090"
echo ""

echo "Note: Replace $SERVER_URL with your actual MCP server URL"