import requests

base = "http://127.0.0.1:5000"

# Login
s = requests.Session()
r = s.post(base + "/login", data={"username": "admin", "password": "admin123"}, allow_redirects=False)
print(f"Login: {r.status_code}")
print(f"Cookies: {dict(s.cookies)}")

# Now try flight-log-merged for image 16
print("\nCalling /api/disk-image/16/flight-log-merged...")
try:
    r2 = s.post(base + "/api/disk-image/16/flight-log-merged", timeout=300)
    print(f"Status: {r2.status_code}")
    print(f"Headers: {dict(r2.headers)}")
    print(f"Body: {r2.text[:2000]}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
