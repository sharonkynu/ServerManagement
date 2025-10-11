#!/usr/bin/env python3
"""
Test script for the Flask API endpoints
"""
import requests
import json

BASE_URL = "http://192.168.18.9:8082"

def test_api_endpoints():
    """Test the API endpoints with authentication"""
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("🔐 Testing API Endpoints...")
    print("=" * 50)
    
    # Step 1: Login
    print("1. Logging in...")
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }
    
    login_response = session.post(f"{BASE_URL}/login", data=login_data)
    print(f"   Login Status: {login_response.status_code}")
    
    if login_response.status_code != 200:
        print("   ❌ Login failed!")
        return False
    
    print("   ✅ Login successful!")
    
    # Step 2: Test check_port_status
    print("\n2. Testing /api/check_port_status...")
    try:
        port_status_response = session.get(f"{BASE_URL}/api/check_port_status")
        print(f"   Status Code: {port_status_response.status_code}")
        
        if port_status_response.status_code == 200:
            data = port_status_response.json()
            print(f"   ✅ Success! Found {len(data.get('ports', []))} ports")
            ports_list = [f"{p['name']} ({p['port']})" for p in data.get('ports', [])]
            print(f"   Ports: {ports_list}")
        else:
            print(f"   ❌ Failed: {port_status_response.text}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 3: Test system_ports
    print("\n3. Testing /api/system_ports...")
    try:
        test_ports = [
            {'id': 'http', 'name': 'HTTP', 'port': 80, 'enabled': True, 'isDefault': True},
            {'id': 'https', 'name': 'HTTPS', 'port': 443, 'enabled': True, 'isDefault': True},
            {'id': 'ssh', 'name': 'SSH', 'port': 22, 'enabled': True, 'isDefault': True}
        ]
        
        system_ports_data = {
            'ports': test_ports,
            'defaultPorts': test_ports,
            'customPorts': []
        }
        
        system_ports_response = session.post(
            f"{BASE_URL}/api/system_ports",
            json=system_ports_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"   Status Code: {system_ports_response.status_code}")
        
        if system_ports_response.status_code == 200:
            data = system_ports_response.json()
            print(f"   ✅ Success! {data.get('message', 'No message')}")
        else:
            print(f"   ❌ Failed: {system_ports_response.text}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 API Test Complete!")
    
    return True

if __name__ == "__main__":
    test_api_endpoints()
