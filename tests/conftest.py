import pytest
import os
import requests
import time
from keycloak import KeycloakAdmin, KeycloakOpenID


@pytest.fixture(scope="session")
def keycloak_config():
    return {
        'server_url': os.getenv('KEYCLOAK_URL', 'http://localhost:8080'),
        'realm_name': os.getenv('TEST_REALM', 'test-realm'),
        'admin_username': os.getenv('KEYCLOAK_ADMIN_USER', 'admin'),
        'admin_password': os.getenv('KEYCLOAK_ADMIN_PASSWORD', 'admin'),
    }


@pytest.fixture(scope="session")
def keycloak_admin(keycloak_config):
    """Initialize Keycloak admin client"""
    admin = KeycloakAdmin(
        server_url=keycloak_config['server_url'],
        username=keycloak_config['admin_username'],
        password=keycloak_config['admin_password'],
        realm_name='master',
        verify=False
    )
    
    # Wait for Keycloak to be ready
    max_retries = 30
    for i in range(max_retries):
        try:
            admin.get_realms()
            break
        except Exception as e:
            if i == max_retries - 1:
                raise Exception(f"Keycloak not ready after {max_retries} attempts: {e}")
            time.sleep(2)
    
    return admin


@pytest.fixture(scope="session")
def oidc_client_config():
    return {
        'client_id': os.getenv('CLIENT_ID', 'oidc-test-client'),
        'client_secret': os.getenv('CLIENT_SECRET', 'oidc-test-secret'),
        'redirect_uri': os.getenv('REDIRECT_URI', 'http://oidc-client/callback')
    }


@pytest.fixture(scope="session")
def oauth2_client_config():
    return {
        'client_id': os.getenv('CLIENT_ID', 'oauth2-api-client'),
        'client_secret': os.getenv('CLIENT_SECRET', 'oauth2-api-secret')
    }


@pytest.fixture(scope="session") 
def test_user_config():
    return {
        'username': os.getenv('TEST_USERNAME', 'testuser'),
        'password': os.getenv('TEST_PASSWORD', 'testpass123'),
        'email': 'testuser@example.com'
    }


@pytest.fixture(scope="session")
def saml_config():
    return {
        'sp_entity_id': os.getenv('SP_ENTITY_ID', 'saml-test-sp'),
        'acs_url': os.getenv('ACS_URL', 'http://saml-sp/acs'),
        'username': 'samluser',
        'password': 'samlpass123'
    }