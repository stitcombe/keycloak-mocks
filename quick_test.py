#!/usr/bin/env python3

import requests
import sys

def test_keycloak_setup():
    keycloak_url = "http://localhost:8080"
    
    print("Testing Keycloak setup...")
    
    # Test 1: Check if Keycloak is running
    try:
        response = requests.get(f"{keycloak_url}/health/ready", timeout=10)
        if response.status_code == 200:
            print("✅ Keycloak health check passed")
        else:
            print(f"❌ Keycloak health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to Keycloak: {e}")
        return False
    
    # Test 2: Check master realm
    try:
        response = requests.get(f"{keycloak_url}/realms/master/.well-known/openid_configuration", timeout=10)
        if response.status_code == 200:
            print("✅ Master realm accessible")
        else:
            print(f"❌ Master realm not accessible: {response.status_code}")
    except Exception as e:
        print(f"❌ Master realm check failed: {e}")
    
    # Test 3: Check test realm
    try:
        response = requests.get(f"{keycloak_url}/realms/test-realm/.well-known/openid_configuration", timeout=10)
        if response.status_code == 200:
            config = response.json()
            print("✅ Test realm accessible")
            print(f"   Issuer: {config.get('issuer', 'N/A')}")
            print(f"   Auth endpoint: {config.get('authorization_endpoint', 'N/A')}")
            return True
        else:
            print(f"❌ Test realm not accessible: {response.status_code}")
            # Try to get admin token and check realms
            print("   Attempting to check available realms...")
            
            admin_token_response = requests.post(
                f"{keycloak_url}/realms/master/protocol/openid-connect/token",
                data={
                    "username": "admin",
                    "password": "admin", 
                    "grant_type": "password",
                    "client_id": "admin-cli"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if admin_token_response.status_code == 200:
                token = admin_token_response.json()["access_token"]
                realms_response = requests.get(
                    f"{keycloak_url}/admin/realms",
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                if realms_response.status_code == 200:
                    realms = realms_response.json()
                    print(f"   Available realms: {[r['realm'] for r in realms]}")
                else:
                    print(f"   Could not fetch realms: {realms_response.status_code}")
            
            return False
            
    except Exception as e:
        print(f"❌ Test realm check failed: {e}")
        return False

if __name__ == "__main__":
    success = test_keycloak_setup()
    sys.exit(0 if success else 1)