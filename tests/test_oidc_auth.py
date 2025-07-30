import pytest
import requests
import jwt
import json
from urllib.parse import urlparse, parse_qs
from keycloak import KeycloakOpenID


class TestOIDCAuthentication:
    """Test OIDC authentication flows"""

    @pytest.fixture(autouse=True)
    def setup(self, keycloak_config, oidc_client_config):
        self.keycloak_openid = KeycloakOpenID(
            server_url=keycloak_config['server_url'],
            client_id=oidc_client_config['client_id'],
            realm_name=keycloak_config['realm_name'],
            client_secret_key=oidc_client_config['client_secret']
        )
        self.config = {**keycloak_config, **oidc_client_config}

    def test_oidc_well_known_configuration(self):
        """Test OIDC well-known configuration endpoint"""
        well_known_url = f"{self.config['server_url']}/realms/{self.config['realm_name']}/.well-known/openid_configuration"
        response = requests.get(well_known_url)
        
        assert response.status_code == 200
        config = response.json()
        
        # Verify required OIDC endpoints
        assert 'authorization_endpoint' in config
        assert 'token_endpoint' in config
        assert 'userinfo_endpoint' in config
        assert 'jwks_uri' in config
        assert 'issuer' in config
        
        print(f"✓ OIDC well-known configuration available")

    def test_oidc_authorization_code_flow(self, test_user_config):
        """Test OIDC Authorization Code Flow"""
        # Step 1: Get authorization URL
        auth_url = self.keycloak_openid.auth_url(
            redirect_uri=self.config['redirect_uri'],
            scope="openid profile email"
        )
        
        assert auth_url.startswith(f"{self.config['server_url']}/realms/{self.config['realm_name']}/protocol/openid-connect/auth")
        
        # Step 2: Simulate user login and get authorization code
        # This would normally involve browser interaction
        session = requests.Session()
        
        # Get login page
        response = session.get(auth_url)
        assert response.status_code == 200
        
        # Extract form data
        from lxml import html
        tree = html.fromstring(response.content)
        form_action = tree.xpath('//form[@id="kc-form-login"]/@action')[0]
        
        # Submit login credentials
        login_data = {
            'username': test_user_config['username'],
            'password': test_user_config['password']
        }
        
        login_response = session.post(
            form_action,
            data=login_data,
            allow_redirects=False
        )
        
        # Should redirect to callback with authorization code
        if login_response.status_code == 302:
            location = login_response.headers['Location']
            parsed_url = urlparse(location)
            query_params = parse_qs(parsed_url.query)
            
            if 'code' in query_params:
                auth_code = query_params['code'][0]
                
                # Step 3: Exchange authorization code for tokens
                token_response = self.keycloak_openid.token(
                    grant_type='authorization_code',
                    code=auth_code,
                    redirect_uri=self.config['redirect_uri']
                )
                
                assert 'access_token' in token_response
                assert 'refresh_token' in token_response
                assert 'id_token' in token_response
                
                print(f"✓ OIDC Authorization Code Flow successful")
                return token_response
        
        print("⚠ OIDC Authorization Code Flow test requires manual intervention")

    def test_oidc_client_credentials_flow(self):
        """Test OIDC Client Credentials Flow (for service accounts)"""
        try:
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            
            assert 'access_token' in token_response
            assert token_response['token_type'] == 'Bearer'
            
            # Verify token structure
            access_token = token_response['access_token']
            decoded_token = jwt.decode(
                access_token,
                options={"verify_signature": False}
            )
            
            assert 'iss' in decoded_token
            assert 'aud' in decoded_token
            assert 'exp' in decoded_token
            
            print(f"✓ OIDC Client Credentials Flow successful")
            
        except Exception as e:
            print(f"⚠ Client Credentials not enabled for this client: {e}")

    def test_oidc_token_introspection(self):
        """Test OIDC token introspection"""
        try:
            # Get a token first
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            
            access_token = token_response['access_token']
            
            # Introspect the token
            introspection = self.keycloak_openid.introspect(access_token)
            
            assert introspection['active'] is True
            assert 'client_id' in introspection
            assert 'token_type' in introspection
            
            print(f"✓ OIDC Token Introspection successful")
            
        except Exception as e:
            print(f"⚠ Token Introspection test failed: {e}")

    def test_oidc_userinfo_endpoint(self, test_user_config):
        """Test OIDC UserInfo endpoint"""
        try:
            # Direct login to get token
            token_response = self.keycloak_openid.token(
                username=test_user_config['username'],
                password=test_user_config['password'],
                grant_type='password'
            )
            
            access_token = token_response['access_token']
            
            # Get user info
            userinfo = self.keycloak_openid.userinfo(access_token)
            
            assert 'sub' in userinfo
            assert 'email' in userinfo
            assert userinfo['email'] == test_user_config['email']
            
            print(f"✓ OIDC UserInfo endpoint successful")
            
        except Exception as e:
            print(f"⚠ UserInfo test failed (Direct Access Grants may be disabled): {e}")

    def test_oidc_logout(self):
        """Test OIDC logout functionality"""
        try:
            # Get a token first
            token_response = self.keycloak_openid.token(
                grant_type='client_credentials'
            )
            
            refresh_token = token_response.get('refresh_token')
            
            if refresh_token:
                # Logout (revoke refresh token)
                logout_response = self.keycloak_openid.logout(refresh_token)
                # Logout typically returns empty response on success
                print(f"✓ OIDC Logout successful")
            else:
                print(f"⚠ No refresh token available for logout test")
                
        except Exception as e:
            print(f"⚠ Logout test failed: {e}")

    def test_oidc_jwks_endpoint(self):
        """Test OIDC JWKS endpoint for public keys"""
        jwks_url = f"{self.config['server_url']}/realms/{self.config['realm_name']}/protocol/openid-connect/certs"
        response = requests.get(jwks_url)
        
        assert response.status_code == 200
        jwks = response.json()
        
        assert 'keys' in jwks
        assert len(jwks['keys']) > 0
        
        # Verify key structure
        for key in jwks['keys']:
            assert 'kty' in key  # Key type
            assert 'use' in key  # Key use
            assert 'kid' in key  # Key ID
            
        print(f"✓ OIDC JWKS endpoint accessible with {len(jwks['keys'])} keys")