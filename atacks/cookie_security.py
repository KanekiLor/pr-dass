#!/usr/bin/env python3

import requests

url_login = "http://127.0.0.1:5000/login"

session = requests.Session()
response = session.get(url_login)

print("Cookie Security Assessment")
print("=" * 40)

credentials = {
    "email": "admin123@mail.com",
    "password": "Parolanoua123"
}

response = session.post(url_login, data=credentials)

if "Logat ca:" in response.text:
    print("Login successful")
    
    cookies = session.cookies.get_dict()
    print(f"Session cookies: {cookies}")
    
    for cookie_name, cookie_value in cookies.items():
        print(f"\nCookie: {cookie_name}")
        print(f"  Value: {cookie_value[:50]}...")
        
        if session.cookies[cookie_name]:
            cookie = session.cookies[cookie_name]
            print(f"  HttpOnly: Check DevTools")
            print(f"  Secure: Check DevTools")
            print(f"  SameSite: Check DevTools")
else:
    print("Login failed")
