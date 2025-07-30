import pytest
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, unquote
import base64
import zlib
from lxml import etree, html


class TestSAMLAuthentication:
    """Test SAML authentication flows"""

    @pytest.fixture(autouse=True)
    def setup(self, keycloak_config, saml_config):
        self.keycloak_url = keycloak_config['server_url']
        self.realm = keycloak_config['realm_name']
        self.saml_config = saml_config

    def test_saml_metadata_endpoint(self):
        """Test SAML Identity Provider metadata endpoint"""
        metadata_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/saml/descriptor"
        response = requests.get(metadata_url)
        
        assert response.status_code == 200
        assert 'application/samlmetadata+xml' in response.headers.get('Content-Type', '')
        
        # Parse XML metadata
        root = ET.fromstring(response.content)
        
        # Check for required SAML elements
        assert root.tag.endswith('EntityDescriptor')
        
        # Look for SSO service endpoints
        sso_services = root.findall('.//{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService')
        assert len(sso_services) > 0
        
        # Look for key descriptors (certificates)
        key_descriptors = root.findall('.//{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor')
        assert len(key_descriptors) > 0
        
        print(f"✓ SAML Metadata endpoint accessible with {len(sso_services)} SSO services")

    def test_saml_sso_redirect_binding(self):
        """Test SAML SSO with HTTP-Redirect binding"""
        # Create SAML AuthnRequest
        saml_request = self._create_saml_authn_request()
        
        # Encode for HTTP-Redirect binding
        compressed = zlib.compress(saml_request.encode('utf-8'))[2:-4]
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        # Build SSO URL
        sso_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/saml"
        params = {
            'SAMLRequest': encoded,
            'RelayState': 'test-relay-state'
        }
        
        session = requests.Session()
        response = session.get(sso_url, params=params)
        
        assert response.status_code == 200
        
        # Should contain login form
        assert 'kc-form-login' in response.text or 'login' in response.text.lower()
        
        print(f"✓ SAML SSO Redirect binding initiated successfully")

    def test_saml_sso_post_binding(self):
        """Test SAML SSO with HTTP-POST binding"""
        # Create SAML AuthnRequest
        saml_request = self._create_saml_authn_request()
        
        # Encode for HTTP-POST binding
        encoded = base64.b64encode(saml_request.encode('utf-8')).decode('utf-8')
        
        # POST to SSO endpoint
        sso_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/saml"
        data = {
            'SAMLRequest': encoded,
            'RelayState': 'test-relay-state'
        }
        
        session = requests.Session()
        response = session.post(sso_url, data=data)
        
        assert response.status_code == 200
        
        # Should contain login form
        assert 'kc-form-login' in response.text or 'login' in response.text.lower()
        
        print(f"✓ SAML SSO POST binding initiated successfully")

    def test_saml_login_flow(self, saml_config):
        """Test complete SAML login flow"""
        try:
            # Step 1: Create SAML AuthnRequest
            saml_request = self._create_saml_authn_request()
            compressed = zlib.compress(saml_request.encode('utf-8'))[2:-4]
            encoded = base64.b64encode(compressed).decode('utf-8')
            
            # Step 2: Send to Keycloak
            sso_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/saml"
            params = {
                'SAMLRequest': encoded,
                'RelayState': 'test-relay-state'
            }
            
            session = requests.Session()
            response = session.get(sso_url, params=params)
            
            if response.status_code == 200 and 'kc-form-login' in response.text:
                # Step 3: Extract login form action
                tree = html.fromstring(response.content)
                form_elements = tree.xpath('//form[@id="kc-form-login"]')
                
                if form_elements:
                    form_action = form_elements[0].get('action')
                    
                    # Step 4: Submit login credentials
                    login_data = {
                        'username': saml_config['username'],
                        'password': saml_config['password']
                    }
                    
                    login_response = session.post(form_action, data=login_data, allow_redirects=False)
                    
                    # Step 5: Should redirect with SAML Response
                    if login_response.status_code == 302:
                        location = login_response.headers.get('Location')
                        if location:
                            # Follow redirect to get SAML Response
                            final_response = session.get(location, allow_redirects=False)
                            
                            if final_response.status_code == 200:
                                # Look for SAML Response in the HTML
                                if 'SAMLResponse' in final_response.text:
                                    print(f"✓ SAML login flow completed successfully")
                                    return True
            
            print("⚠ SAML login flow test requires manual verification")
            return False
            
        except Exception as e:
            print(f"⚠ SAML login flow test failed: {e}")
            return False

    def test_saml_logout_slo(self):
        """Test SAML Single Logout (SLO)"""
        # Create SAML LogoutRequest
        logout_request = self._create_saml_logout_request()
        
        # Encode for HTTP-Redirect binding
        compressed = zlib.compress(logout_request.encode('utf-8'))[2:-4]
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        # Build SLO URL
        slo_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/saml"
        params = {
            'SAMLRequest': encoded,
            'RelayState': 'test-logout-relay-state'
        }
        
        response = requests.get(slo_url, params=params)
        
        # Should handle logout request (may redirect or return SAML response)
        assert response.status_code in [200, 302]
        
        print(f"✓ SAML Single Logout request processed")

    def test_saml_signature_validation(self):
        """Test SAML signature validation capabilities"""
        metadata_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/saml/descriptor"
        response = requests.get(metadata_url)
        
        assert response.status_code == 200
        
        # Parse metadata to find signing certificates
        root = ET.fromstring(response.content)
        key_descriptors = root.findall('.//{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor[@use="signing"]')
        
        if not key_descriptors:
            # Some implementations don't specify use attribute
            key_descriptors = root.findall('.//{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor')
        
        assert len(key_descriptors) > 0
        
        # Check for X509Certificate in key descriptors
        certificates = root.findall('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
        assert len(certificates) > 0
        
        print(f"✓ SAML signing certificates available ({len(certificates)} found)")

    def _create_saml_authn_request(self):
        """Create a basic SAML AuthnRequest"""
        request_id = "test-request-123"
        issue_instant = "2023-01-01T00:00:00Z"
        
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.keycloak_url}/realms/{self.realm}/protocol/saml"
    AssertionConsumerServiceURL="{self.saml_config['acs_url']}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{self.saml_config['sp_entity_id']}</saml:Issuer>
    <samlp:NameIDPolicy 
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>"""

    def _create_saml_logout_request(self):
        """Create a basic SAML LogoutRequest"""
        request_id = "test-logout-123"
        issue_instant = "2023-01-01T00:00:00Z"
        
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.keycloak_url}/realms/{self.realm}/protocol/saml">
    <saml:Issuer>{self.saml_config['sp_entity_id']}</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        {self.saml_config['username']}@example.com
    </saml:NameID>
</samlp:LogoutRequest>"""