import requests

def get_geoip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        if data["status"] == "success":
            return data["lat"], data["lon"]
        else:
            return None, None
    except:
        return None, None
