"""
Charging Kiosk.

Flow:
  1. Franchise operator "boots" the kiosk by entering their FID.
     The kiosk encrypts the FID with ASCON -> VFID, refreshed every boot
     (and on each new session, since nonce is fresh).
  2. Kiosk exposes:
       GET  /qr            -> current VFID ciphertext+nonce (simulated QR)
       POST /pay           -> receive user's encrypted VMID/PIN + amount,
                              forward to Grid, return outcome to user device
       POST /simulate_fail -> kiosk pretends hardware failed after successful
                              payment; triggers a reverse_transaction on Grid
"""
import os
import time
import secrets
import requests
from flask import Flask, request, jsonify

from crypto.ascon import ascon_encrypt
from common.config import ASCON_SHARED_KEY, GRID_URL


app = Flask(__name__)

# Kiosk state
state = {
    "fid": None,
    "vfid_nonce": None,
    "vfid_ct": None,
    "last_tx_id": None,  # for reverse demo
}


def _generate_vfid(fid: str):
    """Encrypt FID under ASCON with a fresh nonce to produce the VFID shown in the QR."""
    nonce = secrets.token_bytes(16)
    ct = ascon_encrypt(ASCON_SHARED_KEY, nonce, fid.encode("ascii"), b"EV-KIOSK-VFID")
    state["vfid_nonce"] = nonce
    state["vfid_ct"]    = ct
    return nonce, ct


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "service": "kiosk", "has_fid": state["fid"] is not None})


@app.route("/boot", methods=["POST"])
def boot():
    """Franchise operator enters FID to bring the kiosk online."""
    j = request.get_json(force=True)
    fid = j["fid"].strip().upper()
    if len(fid) != 16:
        return jsonify({"ok": False, "error": "FID must be 16 hex digits"}), 400
    state["fid"] = fid
    _generate_vfid(fid)
    return jsonify({"ok": True, "fid_set": True})


@app.route("/qr", methods=["GET"])
def qr():
    """User device 'scans' this to get the encrypted VFID."""
    if state["fid"] is None:
        return jsonify({"ok": False, "error": "kiosk not booted"}), 409
    # Refresh nonce every scan to prevent replay
    _generate_vfid(state["fid"])
    return jsonify({
        "ok": True,
        "vfid_ct_hex":    state["vfid_ct"].hex(),
        "vfid_nonce_hex": state["vfid_nonce"].hex(),
    })


@app.route("/pay", methods=["POST"])
def pay():
    """
    User device sends:
      { rsa_ct_vmid: [...], rsa_ct_pin: [...], amount: float, energy_kwh: float,
        vfid_ct_hex, vfid_nonce_hex }
    Kiosk forwards to Grid and returns Grid's verdict.
    """
    if state["fid"] is None:
        return jsonify({"ok": False, "error": "kiosk not booted"}), 409

    j = request.get_json(force=True)
    payload = {
        "vfid_ct_hex":    j["vfid_ct_hex"],
        "vfid_nonce_hex": j["vfid_nonce_hex"],
        "rsa_ct_vmid":    j["rsa_ct_vmid"],
        "rsa_ct_pin":     j["rsa_ct_pin"],
        "amount":         float(j["amount"]),
        "energy_kwh":     float(j.get("energy_kwh", 0.0)),
    }
    try:
        r = requests.post(f"{GRID_URL}/authorize_payment", json=payload, timeout=10)
        data = r.json()
    except Exception as e:
        return jsonify({"ok": False, "error": f"grid unreachable: {e}"}), 502

    if data.get("ok"):
        state["last_tx_id"] = data["tx_id"]
        print(f"[kiosk] Payment APPROVED. tx={data['tx_id']} | dispensing power...")
        # Simulate dispensing
        time.sleep(0.2)
    else:
        print(f"[kiosk] Payment DENIED: {data.get('error')}")
    return jsonify(data), (200 if data.get("ok") else 400)


@app.route("/simulate_fail", methods=["POST"])
def simulate_fail():
    """
    Edge case: hardware failed to dispense power after a successful payment.
    Kiosk requests Grid to record a reverse/refund block.
    """
    tx = state.get("last_tx_id")
    if not tx:
        return jsonify({"ok": False, "error": "no recent transaction to reverse"}), 404
    r = requests.post(f"{GRID_URL}/reverse_transaction",
                      json={"tx_id": tx, "reason": "hardware_failure"}, timeout=10)
    return jsonify(r.json()), r.status_code


def run(host="0.0.0.0", port=5001):
    print(f"[kiosk] Starting Charging Kiosk on {host}:{port} (grid={GRID_URL})")
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    import argparse
    from common.config import KIOSK_PORT
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=KIOSK_PORT)
    args = p.parse_args()
    run(args.host, args.port)
