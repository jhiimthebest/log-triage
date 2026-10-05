"""
Look up where an IP address comes from (country, city, internet provider).
Uses the free ip-api.com service. No account needed.
Test it: python3 ip_lookup.py 8.8.8.8
"""
import json
import sys
import urllib.request


def lookup_ip(ip):
    """Return location info for an IP, or a reason it couldn't be found."""
    if ip.startswith("192.168.") or ip.startswith("10."):
        return {"found": False, "reason": "Internal IP (inside your own network)"}

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read())
    except Exception as error:
        return {"found": False, "reason": f"Lookup failed ({error})"}

    if data.get("status") != "success":
        return {"found": False, "reason": f"No info ({data.get('message', 'unknown')})"}

    return {
        "found": True,
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
    }


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(lookup_ip(ip))
