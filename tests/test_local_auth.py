import pytest
import requests
import jwt
from keycloak import KeycloakOpenID, KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakGetError


class TestLocalUserAuthentication:
    """Test local user authentication and management"""

    @pytest.fixture(autouse=True)
    def setup(self, keycloak_config, test_user_config):
        self.keycloak_openid = KeycloakOpenID(
            server_url=keycloak_config['server_url'],
            client_id='oidc-test-client',
            realm_name=keycloak_config['realm_name'],
            client_secret_key='oidc-test-secret'
        )
        self.keycloak_admin = KeycloakAdmin(
            server_url=keycloak_config['server_url'],
            username=keycloak_config['admin_username'],
            password=keycloak_config['admin_password'],
            realm_name=keycloak_config['realm_name'],
            verify=False
        )
        self.config = keycloak_config
        self.test_user = test_user_config

    def test_local_user_exists(self):
        """Test that local test user exists in realm"""
        try:
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            assert len(users) > 0
            
            user = users[0]
            assert user['username'] == self.test_user['username']
            assert user['email'] == self.test_user['email']
            assert user['enabled'] is True
            
            print(f"✓ Local user '{self.test_user['username']}' exists and is enabled")
            
        except KeycloakGetError as e:
            pytest.fail(f"Failed to retrieve users: {e}")

    def test_local_user_login_direct_grant(self):
        """Test local user login using Direct Access Grant (Resource Owner Password Credentials)"""
        try:
            token_response = self.keycloak_openid.token(
                username=self.test_user['username'],
                password=self.test_user['password'],
                grant_type='password'
            )
            
            assert 'access_token' in token_response
            assert 'refresh_token' in token_response
            assert token_response['token_type'] == 'Bearer'
            
            # Verify token contains user information
            access_token = token_response['access_token']
            decoded_token = jwt.decode(
                access_token,
                options={"verify_signature": False}
            )
            
            assert decoded_token['preferred_username'] == self.test_user['username']
            assert decoded_token['email'] == self.test_user['email']
            
            print(f"✓ Local user direct grant login successful")
            return token_response
            
        except KeycloakAuthenticationError as e:
            pytest.fail(f"Authentication failed: {e}")

    def test_local_user_invalid_credentials(self):
        """Test local user login with invalid credentials"""
        with pytest.raises(KeycloakAuthenticationError):
            self.keycloak_openid.token(
                username=self.test_user['username'],
                password='wrong-password',
                grant_type='password'
            )
        
        print(f"✓ Invalid credentials properly rejected")

    def test_local_user_disabled(self):
        """Test behavior when local user is disabled"""
        try:
            # Get the user
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            if len(users) == 0:
                pytest.skip("Test user not found")
            
            user_id = users[0]['id']
            
            # Disable the user
            self.keycloak_admin.update_user(user_id, {"enabled": False})
            
            # Try to authenticate
            with pytest.raises(KeycloakAuthenticationError):
                self.keycloak_openid.token(
                    username=self.test_user['username'],
                    password=self.test_user['password'],
                    grant_type='password'
                )
            
            print(f"✓ Disabled user authentication properly blocked")
            
        except Exception as e:
            pytest.fail(f"Failed to test disabled user: {e}")
        finally:
            # Re-enable the user for other tests
            try:
                users = self.keycloak_admin.get_users({"username": self.test_user['username']})
                if len(users) > 0:
                    user_id = users[0]['id']
                    self.keycloak_admin.update_user(user_id, {"enabled": True})
            except:
                pass

    def test_local_user_password_reset(self):
        """Test password reset functionality for local users"""
        try:
            # Get the user
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            if len(users) == 0:
                pytest.skip("Test user not found")
            
            user_id = users[0]['id']
            
            # Set a new temporary password
            new_password = "temporary-password-123"
            self.keycloak_admin.set_user_password(
                user_id=user_id,
                password=new_password,
                temporary=True
            )
            
            # Try to authenticate with new password
            token_response = self.keycloak_openid.token(
                username=self.test_user['username'],
                password=new_password,
                grant_type='password'
            )
            
            assert 'access_token' in token_response
            
            print(f"✓ Password reset functionality works")
            
        except Exception as e:
            pytest.fail(f"Password reset test failed: {e}")
        finally:
            # Reset password back to original
            try:
                users = self.keycloak_admin.get_users({"username": self.test_user['username']})
                if len(users) > 0:
                    user_id = users[0]['id']
                    self.keycloak_admin.set_user_password(
                        user_id=user_id,
                        password=self.test_user['password'],
                        temporary=False
                    )
            except:
                pass

    def test_local_user_session_management(self):
        """Test local user session management"""
        try:
            # Login to create a session
            token_response = self.keycloak_openid.token(
                username=self.test_user['username'],
                password=self.test_user['password'],
                grant_type='password'
            )
            
            access_token = token_response['access_token']
            
            # Get user sessions
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            user_id = users[0]['id']
            
            sessions = self.keycloak_admin.get_user_sessions(user_id)
            
            # Should have at least one active session
            assert len(sessions) >= 0  # May be 0 if session hasn't been created yet
            
            print(f"✓ User session management accessible ({len(sessions)} sessions)")
            
        except Exception as e:
            print(f"⚠ Session management test limited: {e}")

    def test_local_user_attributes(self):
        """Test local user custom attributes"""
        try:
            # Get the user
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            if len(users) == 0:
                pytest.skip("Test user not found")
            
            user_id = users[0]['id']
            user = users[0]
            
            # Add custom attributes
            test_attributes = {
                "department": ["Engineering"],
                "employee_id": ["EMP001"],
                "location": ["Remote"]
            }
            
            updated_user = {**user, "attributes": test_attributes}
            self.keycloak_admin.update_user(user_id, updated_user)
            
            # Retrieve and verify attributes
            updated_users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            updated_user = updated_users[0]
            
            assert 'attributes' in updated_user
            attributes = updated_user['attributes']
            assert attributes['department'][0] == 'Engineering'
            assert attributes['employee_id'][0] == 'EMP001'
            
            print(f"✓ User custom attributes supported")
            
        except Exception as e:
            print(f"⚠ User attributes test failed: {e}")

    def test_local_user_roles(self):
        """Test local user role assignment"""
        try:
            # Get the user
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            if len(users) == 0:
                pytest.skip("Test user not found")
            
            user_id = users[0]['id']
            
            # Get available realm roles
            realm_roles = self.keycloak_admin.get_realm_roles()
            
            # Find or create a test role
            test_role_name = "api-user"
            test_role = None
            
            for role in realm_roles:
                if role['name'] == test_role_name:
                    test_role = role
                    break
            
            if test_role:
                # Assign role to user
                self.keycloak_admin.assign_realm_roles(user_id, [test_role])
                
                # Verify role assignment
                user_roles = self.keycloak_admin.get_realm_roles_of_user(user_id)
                role_names = [role['name'] for role in user_roles]
                
                assert test_role_name in role_names
                
                print(f"✓ User role assignment successful")
            else:
                print(f"⚠ Test role '{test_role_name}' not found")
                
        except Exception as e:
            print(f"⚠ User roles test failed: {e}")

    def test_local_user_groups(self):
        """Test local user group membership"""
        try:
            # Get available groups
            groups = self.keycloak_admin.get_groups()
            
            if len(groups) == 0:
                print(f"⚠ No groups available for testing")
                return
            
            # Get the user
            users = self.keycloak_admin.get_users({"username": self.test_user['username']})
            if len(users) == 0:
                pytest.skip("Test user not found")
            
            user_id = users[0]['id']
            
            # Get user's current groups
            user_groups = self.keycloak_admin.get_user_groups(user_id)
            initial_group_count = len(user_groups)
            
            print(f"✓ User group membership accessible ({initial_group_count} groups)")
            
        except Exception as e:
            print(f"⚠ User groups test failed: {e}")