"""
User Device CLI (EV Owner).

Two modes:
  - register: register an EV owner account with the Grid
  - charge:   scan kiosk QR, enter VMID/PIN/amount, send payment

Communication:
  - Registration talks directly to the Grid (setup/enrollment phase).
  - Charging talks to the Kiosk; the Kiosk relays to the Grid.
  - VMID and PIN are encrypted with the Grid's RSA public key end-to-end (so
    even a compromised kiosk cannot learn them -- but a quantum adversary can,
    which is the whole point of the Shor demo).
"""
import sys
import json
import requests

from crypto.quantum import rsa_encrypt_bytes
from common.config import GRID_URL, KIOSK_URL


def register_user_interactive():
    print("\n--- EV Owner Registration ---")
    providers = requests.get(f"{GRID_URL}/providers", timeout=5).json()
    print("Available providers/zones:")
    for pname, zones in providers.items():
        print(f"  {pname}: {', '.join(zones)}")

    name     = input("Full name: ").strip()
    provider = input("Provider (TATA/ADANI/CHARGEPT): ").strip().upper()
    zone     = input("Zone code: ").strip().upper()
    mobile   = input("Mobile number: ").strip()
    password = input("Account password: ").strip()
    pin      = input("Set 4-6 digit PIN: ").strip()
    balance  = float(input("Initial balance (INR): ").strip() or "500")

    r = requests.post(f"{GRID_URL}/register_user", json={
        "name": name, "provider": provider, "zone": zone,
        "mobile": mobile, "password": password, "pin": pin, "balance": balance,
    }, timeout=10)
    print("Response:", json.dumps(r.json(), indent=2))
    return r.json()


def charge_interactive():
    print("\n--- Charging Session ---")
    # 1. Scan QR from kiosk
    qr = requests.get(f"{KIOSK_URL}/qr", timeout=5).json()
    if not qr.get("ok"):
        print("Failed to scan QR:", qr)
        return
    print(f"[scan] VFID ciphertext: {qr['vfid_ct_hex'][:32]}...")
    print(f"[scan] nonce          : {qr['vfid_nonce_hex']}")

    # 2. Fetch Grid RSA public key (end-to-end for PIN/VMID)
    pub = requests.get(f"{GRID_URL}/rsa_pubkey", timeout=5).json()
    print(f"[pk]   Grid RSA pub: N={pub['N']}, e={pub['e']}  (tiny on purpose for Shor demo)")

    # 3. Collect user input
    vmid   = input("Enter your VMID: ").strip().upper()
    pin    = input("Enter your PIN: ").strip()
    amount = float(input("Amount to charge (INR): ").strip())
    energy = float(input("Estimated energy (kWh): ").strip() or "0")

    # 4. RSA-encrypt VMID and PIN
    ct_vmid = rsa_encrypt_bytes(vmid.encode("ascii"), pub)
    ct_pin  = rsa_encrypt_bytes(pin.encode("ascii"),  pub)

    # 5. Submit to kiosk
    r = requests.post(f"{KIOSK_URL}/pay", json={
        "vfid_ct_hex":    qr["vfid_ct_hex"],
        "vfid_nonce_hex": qr["vfid_nonce_hex"],
        "rsa_ct_vmid":    ct_vmid,
        "rsa_ct_pin":     ct_pin,
        "amount":         amount,
        "energy_kwh":     energy,
    }, timeout=15)
    data = r.json()
    print("\nResult:", json.dumps(data, indent=2))
    if data.get("ok"):
        print(f"\n✓ Payment successful. Tx = {data['tx_id'][:16]}...")
        print(f"  Remaining balance: ₹{data['user_balance_after']:.2f}")
    else:
        print(f"\n✗ Payment failed: {data.get('error')}")


def main():
    if len(sys.argv) < 2:
        print("usage: python -m user_device.client [register|charge]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "register":
        register_user_interactive()
    elif cmd == "charge":
        charge_interactive()
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
