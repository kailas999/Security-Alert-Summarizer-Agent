import requests
import json

url = "http://localhost:8000/analyze_alert"
payload = {
    "alert_text": "[ALERT] SSH Brute Force detected from IP 45.12.34.7",
    "model": "gemini/gemini-2.0-flash"
}
headers = {"Content-Type": "application/json"}

try:
    print(f"Sending request to {url}...")
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    print("\nStatus Code:", response.status_code)
    print("\nResponse:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
