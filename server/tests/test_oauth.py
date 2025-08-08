"""Tests for OAuth discovery and registration functionality."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from mcp_auth_server.discovery import discover_authorization_server, AuthorizationServerMetadata, OAuthDiscoveryError
from mcp_auth_server.registration import register_oauth_client, generate_client_name, ClientRegistrationError
from mcp_auth_server.server import setup_oauth_client


class TestOAuthDiscovery:
    """Test OAuth discovery functionality."""
    
    @pytest.mark.asyncio
    async def test_discover_authorization_server_success(self):
        """Test successful OAuth discovery."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "issuer": "http://localhost:9000",
            "authorization_endpoint": "http://localhost:9000/authorize",
            "token_endpoint": "http://localhost:9000/token",
            "introspection_endpoint": "http://localhost:9000/introspect",
            "registration_endpoint": "http://localhost:9000/register",
            "jwks_uri": "http://localhost:9000/.well-known/jwks.json",
        }
        
        with patch("httpx.AsyncClient.get", return_value=mock_response):
            metadata = await discover_authorization_server("http://localhost:9000")
            
            assert metadata.issuer == "http://localhost:9000"
            assert metadata.introspection_endpoint == "http://localhost:9000/introspect"
            assert metadata.registration_endpoint == "http://localhost:9000/register"
    
    @pytest.mark.asyncio
    async def test_discover_authorization_server_404(self):
        """Test discovery with 404 response."""
        mock_response = AsyncMock()
        mock_response.status_code = 404
        
        with patch("httpx.AsyncClient.get", return_value=mock_response):
            with pytest.raises(OAuthDiscoveryError, match="does not support discovery"):
                await discover_authorization_server("http://localhost:9000")

    @pytest.mark.asyncio
    async def test_discover_authorization_server_invalid_json(self):
        """Test discovery with invalid JSON response."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        
        with patch("httpx.AsyncClient.get", return_value=mock_response):
            with pytest.raises(OAuthDiscoveryError, match="Invalid JSON"):
                await discover_authorization_server("http://localhost:9000")

    @pytest.mark.asyncio
    async def test_discover_authorization_server_missing_required_fields(self):
        """Test discovery with missing required fields."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "issuer": "http://localhost:9000",
            # Missing introspection_endpoint and registration_endpoint
        }
        
        with patch("httpx.AsyncClient.get", return_value=mock_response):
            with pytest.raises(OAuthDiscoveryError, match="Missing required"):
                await discover_authorization_server("http://localhost:9000")


class TestOAuthRegistration:
    """Test OAuth client registration functionality."""
    
    def test_generate_client_name(self):
        """Test client name generation."""
        name1 = generate_client_name()
        name2 = generate_client_name()
        
        assert name1.startswith("MCP Auth Server-")
        assert name2.startswith("MCP Auth Server-")
        assert name1 != name2  # Should be unique

    def test_generate_client_name_custom_base(self):
        """Test client name generation with custom base."""
        name = generate_client_name("Custom Server")
        assert name.startswith("Custom Server-")
        assert len(name) > len("Custom Server-")
    
    @pytest.mark.asyncio
    async def test_register_oauth_client_success(self):
        """Test successful OAuth client registration."""
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "client_id": "test-client-123",
            "client_secret": "secret-456",
            "client_name": "Test Client",
            "redirect_uris": ["http://localhost:8001/oauth/callback"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            client = await register_oauth_client(
                registration_endpoint="http://localhost:9000/register",
                client_name="Test Client",
                server_url="http://localhost:8001",
            )
            
            assert client.client_id == "test-client-123"
            assert client.client_secret == "secret-456"
            assert client.client_name == "Test Client"
            assert client.grant_types == ["client_credentials"]
    
    @pytest.mark.asyncio
    async def test_register_oauth_client_missing_client_id(self):
        """Test registration failure when client_id is missing."""
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            # Missing client_id
            "client_secret": "secret-456",
            "client_name": "Test Client",
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(ClientRegistrationError, match="Missing client_id"):
                await register_oauth_client(
                    registration_endpoint="http://localhost:9000/register",
                    client_name="Test Client",
                    server_url="http://localhost:8001",
                )
    
    @pytest.mark.asyncio
    async def test_register_oauth_client_missing_secret(self):
        """Test registration failure when client_secret is missing."""
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "client_id": "test-client-123",
            # Missing client_secret
            "client_name": "Test Client",
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(ClientRegistrationError, match="Missing client_secret"):
                await register_oauth_client(
                    registration_endpoint="http://localhost:9000/register",
                    client_name="Test Client",
                    server_url="http://localhost:8001",
                )

    @pytest.mark.asyncio
    async def test_register_oauth_client_400_error(self):
        """Test registration failure with 400 Bad Request."""
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": "invalid_redirect_uri",
            "error_description": "Invalid redirect URI provided"
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(ClientRegistrationError, match="Invalid redirect URI"):
                await register_oauth_client(
                    registration_endpoint="http://localhost:9000/register",
                    client_name="Test Client",
                    server_url="http://localhost:8001",
                )

    @pytest.mark.asyncio
    async def test_register_oauth_client_network_error(self):
        """Test registration failure with network error."""
        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Network error")):
            with pytest.raises(ClientRegistrationError, match="Network error"):
                await register_oauth_client(
                    registration_endpoint="http://localhost:9000/register",
                    client_name="Test Client",
                    server_url="http://localhost:8001",
                )


class TestOAuthClientSetup:
    """Test OAuth client setup integration."""
    
    @pytest.mark.asyncio
    async def test_setup_oauth_client_success(self):
        """Test successful OAuth client setup."""
        # Mock discovery response
        discovery_metadata = {
            "issuer": "http://localhost:9000",
            "introspection_endpoint": "http://localhost:9000/introspect",
            "registration_endpoint": "http://localhost:9000/register",
        }
        
        # Mock registration response
        with patch("mcp_auth_server.server.discover_authorization_server") as mock_discovery, \
             patch("mcp_auth_server.server.register_oauth_client") as mock_registration:
            
            mock_discovery.return_value = AuthorizationServerMetadata(discovery_metadata)
            mock_registration.return_value = MagicMock(
                client_id="test-client-123",
                client_secret="secret-456",
                client_name="Test Client",
            )
            
            client = await setup_oauth_client(
                auth_server_url="http://localhost:9000",
                server_url="http://localhost:8001",
                client_name="Test Client",
            )
            
            assert client.client_id == "test-client-123"
            assert client.client_secret == "secret-456"
            mock_discovery.assert_called_once_with("http://localhost:9000")
            mock_registration.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_oauth_client_discovery_failure(self):
        """Test OAuth client setup with discovery failure."""
        with patch("mcp_auth_server.server.discover_authorization_server") as mock_discovery:
            mock_discovery.side_effect = OAuthDiscoveryError("Discovery failed")
            
            with pytest.raises(OAuthDiscoveryError, match="Failed to discover OAuth endpoints"):
                await setup_oauth_client(
                    auth_server_url="http://localhost:9000",
                    server_url="http://localhost:8001",
                    client_name="Test Client",
                )

    @pytest.mark.asyncio
    async def test_setup_oauth_client_registration_failure(self):
        """Test OAuth client setup with registration failure."""
        discovery_metadata = {
            "issuer": "http://localhost:9000",
            "introspection_endpoint": "http://localhost:9000/introspect",
            "registration_endpoint": "http://localhost:9000/register",
        }
        
        with patch("mcp_auth_server.server.discover_authorization_server") as mock_discovery, \
             patch("mcp_auth_server.server.register_oauth_client") as mock_registration:
            
            mock_discovery.return_value = AuthorizationServerMetadata(discovery_metadata)
            mock_registration.side_effect = ClientRegistrationError("Registration failed")
            
            with pytest.raises(ClientRegistrationError, match="Failed to register OAuth client"):
                await setup_oauth_client(
                    auth_server_url="http://localhost:9000",
                    server_url="http://localhost:8001",
                    client_name="Test Client",
                )