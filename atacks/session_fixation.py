#!/usr/bin/env python3

import requests

url_login = "http://127.0.0.1:5000/login"
url_profile = "http://127.0.0.1:5000/profile"

session = requests.Session()
response = session.get(url_login)

initial_cookies = session.cookies.get_dict()
print("Cookies before login:", initial_cookies)

credentials = {
    "email": "admin123@mail.com",
    "password": "Parolanoua123"
}

response = session.post(url_login, data=credentials)

if "Logat ca:" not in response.text:
    print("Login failed")
    exit(1)

after_login_cookies = session.cookies.get_dict()
print("Cookies after login:", after_login_cookies)

if initial_cookies.get("session") == after_login_cookies.get("session"):
    print("Vulnerability: Session ID did not regenerate after login")
else:
    print("Session ID was regenerated (correct behavior)")
