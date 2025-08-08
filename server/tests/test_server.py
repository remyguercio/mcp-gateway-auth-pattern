"""Tests for MCP Auth Server."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from mcp_auth_server.auth import IntrospectionTokenVerifier, create_token_verifier
from mcp_auth_server.discovery import discover_authorization_server, AuthorizationServerMetadata, OAuthDiscoveryError
from mcp_auth_server.registration import register_oauth_client, generate_client_name, ClientRegistrationError
from mcp_auth_server.server import setup_oauth_client


class TestIntrospectionTokenVerifier:
    """Test OAuth token verification."""
    
    def test_validate_introspection_url_https(self):
        """Test HTTPS URLs are accepted."""
        verifier = IntrospectionTokenVerifier(
            introspection_endpoint="https://auth.example.com/introspect",
            server_url="https://server.example.com",
        )
        assert verifier.introspection_endpoint == "https://auth.example.com/introspect"
    
    def test_validate_introspection_url_localhost(self):
        """Test localhost HTTP URLs are accepted."""
        verifier = IntrospectionTokenVerifier(
            introspection_endpoint="http://localhost:9000/introspect",
            server_url="http://localhost:8001",
        )
        assert verifier.introspection_endpoint == "http://localhost:9000/introspect"
    
    def test_validate_introspection_url_invalid(self):
        """Test invalid URLs are rejected."""
        with pytest.raises(ValueError):
            IntrospectionTokenVerifier(
                introspection_endpoint="http://malicious.com/introspect",
                server_url="http://localhost:8001",
            )
    
    @pytest.mark.asyncio
    async def test_verify_token_valid_with_client_auth(self):
        """Test valid token verification with client authentication."""
        verifier = IntrospectionTokenVerifier(
            introspection_endpoint="http://localhost:9000/introspect",
            server_url="http://localhost:8001",
            client_id="test-client",
            client_secret="test-secret",
        )
        
        # Mock successful introspection response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "active": True,
            "client_id": "test-client",
            "scope": "mcp:access read",
            "exp": 9999999999,  # Far future
            "sub": "user123",
            "iss": "http://localhost:9000",
            "aud": "http://localhost:8001",
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            token_info = await verifier.verify_token("valid-token")
            
            # Verify client authentication was included
            call_args = mock_post.call_args
            assert call_args[1]["data"]["client_id"] == "test-client"
            assert call_args[1]["data"]["client_secret"] == "test-secret"
            assert call_args[1]["data"]["token"] == "valid-token"
            
            assert token_info is not None
            assert token_info.client_id == "test-client"
            assert token_info.scopes == ["mcp:access", "read"]
            assert token_info.subject == "user123"
    
    @pytest.mark.asyncio
    async def test_verify_token_inactive(self):
        """Test inactive token rejection."""
        verifier = IntrospectionTokenVerifier(
            introspection_endpoint="http://localhost:9000/introspect",
            server_url="http://localhost:8001",
        )
        
        # Mock inactive token response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"active": False}
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            token_info = await verifier.verify_token("inactive-token")
            assert token_info is None
    
    @pytest.mark.asyncio
    async def test_verify_token_network_error(self):
        """Test network error handling."""
        verifier = IntrospectionTokenVerifier(
            introspection_endpoint="http://localhost:9000/introspect",
            server_url="http://localhost:8001",
        )
        
        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Network error")):
            token_info = await verifier.verify_token("any-token")
            assert token_info is None


class TestServerCreation:
    """Test MCP server creation and configuration."""
    
    def test_create_server_basic(self):
        """Test basic server creation."""
        server = create_server(
            auth_server_url="http://localhost:9000",
            host="localhost",
            port=8001,
        )
        
        assert server.name == "MCP OAuth Resource Server"
        assert server.host == "localhost"
        assert server.port == 8001
    
    def test_create_server_with_scopes(self):
        """Test server creation with custom scopes."""
        server = create_server(
            auth_server_url="http://localhost:9000",
            required_scopes=["custom:scope", "other:scope"],
        )
        
        assert server.auth.required_scopes == ["custom:scope", "other:scope"]
    
    def test_create_token_verifier_helper(self):
        """Test token verifier creation helper."""
        verifier = create_token_verifier(
            auth_server_url="http://localhost:9000",
            server_url="http://localhost:8001",
        )
        
        assert verifier.introspection_endpoint == "http://localhost:9000/introspect"
        assert verifier.server_url == "http://localhost:8001"
        assert verifier.validate_resource is True