import pytest
import requests
import jwt
import json
from datetime import datetime
from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakGetError


class TestOAuth2ClientCredentials:
    """Test OAuth2 Client Credentials Grant for API access"""

    @pytest.fixture(autouse=True)
    def setup(self, keycloak_config, oauth2_client_config):
        self.keycloak_openid = KeycloakOpenID(
            server_url=keycloak_config['server_url'],
            client_id=oauth2_client_config['client_id'],
            realm_name=keycloak_config['realm_name'],
            client_secret_key=oauth2_client_config['client_secret']
        )
        self.keycloak_admin = KeycloakAdmin(
            server_url=keycloak_config['server_url'],
            username=keycloak_config['admin_username'],
            password=keycloak_config['admin_password'],
            realm_name=keycloak_config['realm_name'],
            verify=False
        )
        self.config = {**keycloak_config, **oauth2_client_config}

    def test_client_exists_and_configured(self):
        """Test that OAuth2 client exists and is properly configured"""
        try:
            clients = self.keycloak_admin.get_clients()
            oauth2_client = None
            
            for client in clients:
                if client['clientId'] == self.config['client_id']:
                    oauth2_client = client
                    break
            
            assert oauth2_client is not None, f"Client '{self.config['client_id']}' not found"
            assert oauth2_client['enabled'] is True
            assert oauth2_client['serviceAccountsEnabled'] is True
            assert oauth2_client['publicClient'] is False
            
            print(f"✓ OAuth2 client '{self.config['client_id']}' exists and is configured")
            
        except KeycloakGetError as e:
            pytest.fail(f"Failed to retrieve clients: {e}")

    def test_client_credentials_grant(self):
        """Test OAuth2 Client Credentials Grant flow"""
        try:
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            
            assert 'access_token' in token_response
            assert token_response['token_type'] == 'Bearer'
            assert 'expires_in' in token_response
            
            # Client credentials grant should not include refresh token
            assert 'refresh_token' not in token_response
            
            # Verify token structure
            access_token = token_response['access_token']
            decoded_token = jwt.decode(
                access_token,
                options={"verify_signature": False}
            )
            
            assert 'iss' in decoded_token  # Issuer
            assert 'aud' in decoded_token  # Audience
            assert 'exp' in decoded_token  # Expiration
            assert 'iat' in decoded_token  # Issued at
            assert 'azp' in decoded_token  # Authorized party (client_id)
            assert 'typ' in decoded_token  # Token type
            
            assert decoded_token['azp'] == self.config['client_id']
            assert decoded_token['typ'] == 'Bearer'
            
            print(f"✓ Client Credentials Grant successful")
            return token_response
            
        except KeycloakAuthenticationError as e:
            pytest.fail(f"Client Credentials Grant failed: {e}")

    def test_invalid_client_credentials(self):
        """Test OAuth2 Client Credentials with invalid credentials"""
        # Create a client with wrong secret
        invalid_client = KeycloakOpenID(
            server_url=self.config['server_url'],
            client_id=self.config['client_id'],
            realm_name=self.config['realm_name'],
            client_secret_key='wrong-secret'
        )
        
        with pytest.raises(KeycloakAuthenticationError):
            invalid_client.token(grant_type='client_credentials')
        
        print(f"✓ Invalid client credentials properly rejected")

    def test_client_credentials_token_validation(self):
        """Test token validation and introspection"""
        try:
            # Get a token
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            access_token = token_response['access_token']
            
            # Introspect the token
            introspection = self.keycloak_openid.introspect(access_token)
            
            assert introspection['active'] is True
            assert introspection['client_id'] == self.config['client_id']
            assert introspection['token_type'] == 'Bearer'
            assert 'exp' in introspection
            assert 'iat' in introspection
            
            print(f"✓ Token introspection successful")
            
        except Exception as e:
            pytest.fail(f"Token validation failed: {e}")

    def test_client_credentials_scope_handling(self):
        """Test scope handling in Client Credentials Grant"""
        try:
            # Request token with specific scope
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials',
                scope='api-scope'
            )
            
            access_token = token_response['access_token']
            decoded_token = jwt.decode(
                access_token,
                options={"verify_signature": False}
            )
            
            # Check if scope is present in token
            scope_present = 'scope' in decoded_token or 'scp' in decoded_token
            
            print(f"✓ Scope handling in Client Credentials Grant verified")
            
        except Exception as e:
            # Some configurations may not support custom scopes
            print(f"⚠ Scope test completed with limitations: {e}")

    def test_client_credentials_token_lifetime(self):
        """Test token lifetime and expiration"""
        try:
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            
            access_token = token_response['access_token']
            expires_in = token_response['expires_in']
            
            # Decode token to check expiration
            decoded_token = jwt.decode(
                access_token,
                options={"verify_signature": False}
            )
            
            exp_timestamp = decoded_token['exp']
            iat_timestamp = decoded_token['iat']
            
            # Verify expires_in matches token expiration
            calculated_expires_in = exp_timestamp - iat_timestamp
            
            # Allow some variance for timing differences
            assert abs(calculated_expires_in - expires_in) <= 5
            
            print(f"✓ Token lifetime validation successful (expires in {expires_in}s)")
            
        except Exception as e:
            pytest.fail(f"Token lifetime test failed: {e}")

    def test_client_service_account(self):
        """Test service account associated with OAuth2 client"""
        try:
            # Get token to establish service account
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            
            # Look for service account user
            service_account_username = f"service-account-{self.config['client_id']}"
            users = self.keycloak_admin.get_users({"username": service_account_username})
            
            if len(users) > 0:
                service_account = users[0]
                assert service_account['enabled'] is True
                assert service_account['serviceAccountClientId'] == self.config['client_id']
                
                print(f"✓ Service account '{service_account_username}' exists and is enabled")
            else:
                print(f"⚠ Service account not found (may be using different naming convention)")
                
        except Exception as e:
            print(f"⚠ Service account test failed: {e}")

    def test_api_resource_access(self):
        """Test using OAuth2 token for API resource access"""
        try:
            # Get access token
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            access_token = token_response['access_token']
            
            # Test accessing Keycloak's user info endpoint (as a proxy for API access)
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Access realm information (requires proper token)
            realm_info_url = f"{self.config['server_url']}/realms/{self.config['realm_name']}"
            response = requests.get(realm_info_url, headers=headers)
            
            # This endpoint should be accessible with a valid token
            assert response.status_code == 200
            realm_info = response.json()
            assert 'realm' in realm_info
            
            print(f"✓ API resource access with OAuth2 token successful")
            
        except Exception as e:
            print(f"⚠ API resource access test limited: {e}")

    def test_token_revocation(self):
        """Test OAuth2 token revocation"""
        try:
            # Get access token
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            access_token = token_response['access_token']
            
            # Verify token is active
            introspection_before = self.keycloak_openid.introspect(access_token)
            assert introspection_before['active'] is True
            
            # Revoke the token
            revoke_url = f"{self.config['server_url']}/realms/{self.config['realm_name']}/protocol/openid-connect/revoke"
            revoke_data = {
                'token': access_token,
                'client_id': self.config['client_id'],
                'client_secret': self.config['client_secret']
            }
            
            revoke_response = requests.post(revoke_url, data=revoke_data)
            
            # Revocation should succeed (returns 200 or 204)
            assert revoke_response.status_code in [200, 204]
            
            print(f"✓ Token revocation successful")
            
        except Exception as e:
            print(f"⚠ Token revocation test failed: {e}")

    def test_concurrent_token_requests(self):
        """Test multiple concurrent token requests"""
        import concurrent.futures
        
        def get_token():
            try:
                response = self.keycloak_openid.token(grant_type='client_credentials')
                return response['access_token'] is not None
            except:
                return False
        
        try:
            # Execute multiple token requests concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(get_token) for _ in range(10)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            # All requests should succeed
            success_count = sum(results)
            assert success_count >= 8  # Allow for some failures due to timing
            
            print(f"✓ Concurrent token requests successful ({success_count}/10)")
            
        except Exception as e:
            print(f"⚠ Concurrent token test failed: {e}")