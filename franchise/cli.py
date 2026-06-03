"""
Franchise CLI -- used by the station owner to:
  - Register a franchise account with the Grid
  - Boot the kiosk with the franchise's FID
"""
import sys
import json
import requests

from common.config import GRID_URL, KIOSK_URL


def register_franchise_interactive():
    print("\n--- Franchise Registration ---")
    providers = requests.get(f"{GRID_URL}/providers", timeout=5).json()
    print("Available providers/zones:")
    for pname, zones in providers.items():
        print(f"  {pname}: {', '.join(zones)}")

    name     = input("Franchise/Station name: ").strip()
    provider = input("Provider (TATA/ADANI/CHARGEPT): ").strip().upper()
    zone     = input("Zone code: ").strip().upper()
    password = input("Account password: ").strip()
    balance  = float(input("Initial balance (INR): ").strip() or "0")

    r = requests.post(f"{GRID_URL}/register_franchise", json={
        "name": name, "provider": provider, "zone": zone,
        "password": password, "balance": balance,
    }, timeout=10)
    print("Response:", json.dumps(r.json(), indent=2))


def boot_kiosk_interactive():
    print("\n--- Boot Kiosk ---")
    fid = input("Enter Franchise ID (16 hex): ").strip().upper()
    r = requests.post(f"{KIOSK_URL}/boot", json={"fid": fid}, timeout=5)
    print("Response:", json.dumps(r.json(), indent=2))


def main():
    if len(sys.argv) < 2:
        print("usage: python -m franchise.cli [register|boot]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "register":
        register_franchise_interactive()
    elif cmd == "boot":
        boot_kiosk_interactive()
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
