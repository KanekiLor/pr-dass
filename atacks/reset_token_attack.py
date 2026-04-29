#!/usr/bin/env python3

import requests
import re

url_forgot = "http://127.0.0.1:5000/forgot-password"
url_reset = "http://127.0.0.1:5000/forgot-password"

emails = ["test1@mail.com", "test2@mail.com", "admin@mail.com"]

for email in emails:
    data = {"email": email}
    response = requests.post(url_forgot, data=data)
    
    if "Link de resetare:" in response.text or "forgot-password/" in response.text:
        match = re.search(r"forgot-password/(\d+)", response.text)
        if match:
            token = match.group(1)
            print(f"{email}: token={token}")
            
            reset_url = f"{url_reset}/{token}"
            print(f"  Reset link: {reset_url}")
        else:
            print(f"{email}: Token found but could not extract")
    else:
        print(f"{email}: No token")
