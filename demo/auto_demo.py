"""
End-to-end automated demo.

Starts the Grid and Kiosk servers in background threads, then exercises
the entire flow:
  1. Register 2 franchises and 2 users across different providers
  2. Boot the kiosk with one franchise's FID -> VFID generated & shown
  3. User scans QR, pays successfully -> block added
  4. Show blockchain state
  5. Negative cases:
       - wrong PIN
       - insufficient balance
       - cross-provider rejection
  6. Simulate hardware failure -> reverse block
  7. Shor demo: adversary captures RSA pubkey + an RSA-encrypted PIN, breaks it

Run:
    python -m demo.auto_demo
"""
import os
import time
import json
import threading
import requests

# Make sure we can import project modules when run via `python -m demo.auto_demo`
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grid import server as grid_server
from kiosk import server as kiosk_server
from crypto.quantum import rsa_encrypt_bytes, shor_break_rsa
from common.config import GRID_URL, KIOSK_URL, GRID_PORT, KIOSK_PORT


def hr(title=""):
    print("\n" + "=" * 70)
    if title: print(f"  {title}")
    print("=" * 70)


def wait_for(url, timeout=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(url, timeout=1)
            if r.ok: return True
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"server at {url} did not come up")


def start_servers():
    t_grid = threading.Thread(
        target=grid_server.run, kwargs={"host": "127.0.0.1", "port": GRID_PORT}, daemon=True)
    t_kiosk = threading.Thread(
        target=kiosk_server.run, kwargs={"host": "127.0.0.1", "port": KIOSK_PORT}, daemon=True)
    t_grid.start()
    t_kiosk.start()
    wait_for(f"{GRID_URL}/ping")
    wait_for(f"{KIOSK_URL}/ping")
    print("[demo] Grid and Kiosk are up.")


def post(url, payload):
    r = requests.post(url, json=payload, timeout=10)
    return r.json(), r.status_code


def main():
    hr("STARTING SERVERS")
    start_servers()

    hr("1. REGISTRATION")
    # Franchises
    f1, _ = post(f"{GRID_URL}/register_franchise", {
        "name": "TataPower-Hyd-01", "provider": "TATA", "zone": "TATA-Z01",
        "password": "tata-secret", "balance": 0.0,
    })
    f2, _ = post(f"{GRID_URL}/register_franchise", {
        "name": "Adani-Hyd-02", "provider": "ADANI", "zone": "ADANI-Z02",
        "password": "adani-secret", "balance": 0.0,
    })
    print("Franchise 1:", f1)
    print("Franchise 2:", f2)

    # Users
    u1, _ = post(f"{GRID_URL}/register_user", {
        "name": "Alice", "provider": "TATA", "zone": "TATA-Z01",
        "mobile": "9990000001", "password": "alicepw", "pin": "4321",
        "balance": 1000.0,
    })
    u2, _ = post(f"{GRID_URL}/register_user", {
        "name": "Bob", "provider": "ADANI", "zone": "ADANI-Z02",
        "mobile": "9990000002", "password": "bobpw", "pin": "1111",
        "balance": 50.0,  # low balance on purpose
    })
    print("User 1 (Alice):", u1)
    print("User 2 (Bob)  :", u2)

    hr("2. BOOT KIOSK WITH TATA FID")
    boot, _ = post(f"{KIOSK_URL}/boot", {"fid": f1["fid"]})
    print("Kiosk boot:", boot)

    qr = requests.get(f"{KIOSK_URL}/qr", timeout=5).json()
    print("QR contents (encrypted VFID):")
    print(f"  vfid_ct = {qr['vfid_ct_hex']}")
    print(f"  nonce   = {qr['vfid_nonce_hex']}")

    # Grid RSA pub (tiny)
    pub = requests.get(f"{GRID_URL}/rsa_pubkey").json()
    print(f"\n  Grid RSA public key: N={pub['N']}, e={pub['e']}")

    def make_pay_payload(vmid, pin, amount, energy, qr_data):
        return {
            "vfid_ct_hex":    qr_data["vfid_ct_hex"],
            "vfid_nonce_hex": qr_data["vfid_nonce_hex"],
            "rsa_ct_vmid":    rsa_encrypt_bytes(vmid.encode(), pub),
            "rsa_ct_pin":     rsa_encrypt_bytes(pin.encode(),  pub),
            "amount":         amount,
            "energy_kwh":     energy,
        }

    hr("3. HAPPY PATH: Alice charges at Tata station (₹250)")
    res, _ = post(f"{KIOSK_URL}/pay",
                  make_pay_payload(u1["vmid"], "4321", 250.0, 12.5, qr))
    print("Result:", json.dumps(res, indent=2))
    alice_tx = res.get("tx_id")

    hr("4. NEGATIVE: wrong PIN")
    qr2 = requests.get(f"{KIOSK_URL}/qr").json()
    res, _ = post(f"{KIOSK_URL}/pay",
                  make_pay_payload(u1["vmid"], "9999", 100.0, 5.0, qr2))
    print("Result:", res)

    hr("5. NEGATIVE: Bob has insufficient balance (needs ADANI kiosk)")
    # Re-boot kiosk as Adani franchise for Bob
    post(f"{KIOSK_URL}/boot", {"fid": f2["fid"]})
    qr3 = requests.get(f"{KIOSK_URL}/qr").json()
    res, _ = post(f"{KIOSK_URL}/pay",
                  make_pay_payload(u2["vmid"], "1111", 500.0, 20.0, qr3))
    print("Result:", res)

    hr("6. NEGATIVE: cross-provider (Alice tries Adani station)")
    res, _ = post(f"{KIOSK_URL}/pay",
                  make_pay_payload(u1["vmid"], "4321", 100.0, 5.0, qr3))
    print("Result:", res)

    hr("7. EDGE CASE: hardware failure after successful payment -> reverse block")
    # Re-boot as Tata, Alice pays again, then we simulate failure
    post(f"{KIOSK_URL}/boot", {"fid": f1["fid"]})
    qr4 = requests.get(f"{KIOSK_URL}/qr").json()
    res, _ = post(f"{KIOSK_URL}/pay",
                  make_pay_payload(u1["vmid"], "4321", 75.0, 3.0, qr4))
    print("Second Alice payment:", res)
    rev = requests.post(f"{KIOSK_URL}/simulate_fail", timeout=5).json()
    print("Reverse block created:", rev)

    hr("8. BLOCKCHAIN STATE")
    chain = requests.get(f"{GRID_URL}/chain").json()
    print(f"Chain length: {chain['length']}, valid: {chain['valid']}")
    for b in chain["chain"]:
        tag = " [DISPUTE]" if b["dispute_flag"] else ""
        print(f"  #{b['index']}{tag} tx={b['tx_id'][:16]}... uid={b['uid'][:8]}... "
              f"fid={b['fid'][:8]}... amt={b['amount']} kwh={b['energy_kwh']}")

    hr("9. FINAL ACCOUNT BALANCES")
    accts = requests.get(f"{GRID_URL}/accounts").json()
    for fid, f in accts["franchises"].items():
        print(f"  Franchise {f['name']:20s} [{fid[:8]}...] balance = ₹{f['balance']:.2f}")
    for uid, u in accts["users"].items():
        print(f"  User      {u['name']:20s} [{uid[:8]}...] balance = ₹{u['balance']:.2f}")

    hr("10. QUANTUM ATTACK: Shor's Algorithm breaks the RSA layer")
    print("An eavesdropper captured the Grid's RSA public key and one RSA-encrypted PIN.")
    print("Using Shor's algorithm, they factor N and recover the plaintext PIN.\n")
    secret_pin = "4321"
    captured_ct = rsa_encrypt_bytes(secret_pin.encode(), pub)
    print(f"Captured ciphertext ints: {captured_ct}")
    recovered = shor_break_rsa(pub, captured_ct, verbose=True)
    print(f"\n>>> Recovered plaintext PIN: {recovered.decode(errors='replace')}")
    print(">>> This demonstrates why post-quantum cryptography is required for")
    print(">>> transporting user credentials in smart-grid/EV networks.")

    hr("DEMO COMPLETE")


if __name__ == "__main__":
    main()
