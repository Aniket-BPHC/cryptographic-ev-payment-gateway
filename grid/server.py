"""
Grid Authority server.

Exposes HTTP endpoints to:
  - Register franchises and users
  - Validate a payment request (VMID + PIN + VFID + amount)
  - Record valid transactions on the blockchain
  - Expose blockchain state for auditing

The Grid holds:
  - provider/zone catalog
  - franchise accounts (FID, zone, balance, password hash)
  - user accounts (UID, zone, balance, PIN hash, mobile, VMID)
  - blockchain ledger
  - RSA keypair (intentionally tiny -- for Shor demo)

All credentials in transit from the user device to the Grid are tunnelled through
RSA (to be broken by Shor). The VFID is encrypted with ASCON by the kiosk.
"""
import os
import time
import json
import secrets
from threading import Lock
from flask import Flask, request, jsonify

from crypto.ascon import ascon_decrypt
from crypto.hashing import generate_16_digit_id, hash_pin, sha3_hex
from crypto.quantum import rsa_keygen, rsa_decrypt_bytes
from blockchain.ledger import Blockchain
from common.config import ASCON_SHARED_KEY, GRID_PROVIDERS, DATA_DIR


app = Flask(__name__)

# ---------- In-memory state ----------
franchises = {}   # fid -> {name, zone, provider, password_hash, balance}
users      = {}   # uid -> {name, zone, provider, pin_salt, pin_hash, mobile, vmid, balance}
vmid_index = {}   # vmid -> uid  (fast lookup)

ledger = Blockchain()
state_lock = Lock()

# RSA keys for PIN/VMID transport (tiny, on purpose)
RSA_KEY = rsa_keygen(bits_per_prime=7)
RSA_PUB = {"N": RSA_KEY["N"], "e": RSA_KEY["e"]}
RSA_PRIV = {"N": RSA_KEY["N"], "d": RSA_KEY["d"]}


def _persist():
    """Snapshot state to disk (best-effort, for inspection)."""
    try:
        with open(os.path.join(DATA_DIR, "grid_state.json"), "w") as f:
            json.dump({
                "franchises": franchises,
                "users": {k: {kk: vv for kk, vv in v.items()} for k, v in users.items()},
                "chain": ledger.to_list(),
            }, f, indent=2, default=str)
    except Exception as e:
        print(f"[grid] persist warning: {e}")


# ---------- Public endpoints ----------
@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "service": "grid_authority", "time": time.time()})


@app.route("/rsa_pubkey", methods=["GET"])
def get_rsa_pub():
    """Public key used by the user device to encrypt PIN/VMID."""
    return jsonify(RSA_PUB)


@app.route("/providers", methods=["GET"])
def providers():
    return jsonify(GRID_PROVIDERS)


@app.route("/register_franchise", methods=["POST"])
def register_franchise():
    j = request.get_json(force=True)
    name     = j["name"]
    provider = j["provider"]
    zone     = j["zone"]
    password = j["password"]
    balance  = float(j.get("balance", 0.0))

    if provider not in GRID_PROVIDERS or zone not in GRID_PROVIDERS[provider]:
        return jsonify({"ok": False, "error": "invalid provider/zone"}), 400

    fid = generate_16_digit_id(name, password)
    with state_lock:
        if fid in franchises:
            return jsonify({"ok": False, "error": "fid collision, retry"}), 500
        franchises[fid] = {
            "name": name,
            "provider": provider,
            "zone": zone,
            "password_hash": sha3_hex(password.encode()),
            "balance": balance,
            "created": time.time(),
        }
        _persist()
    return jsonify({"ok": True, "fid": fid})


@app.route("/register_user", methods=["POST"])
def register_user():
    j = request.get_json(force=True)
    name     = j["name"]
    provider = j["provider"]
    zone     = j["zone"]
    password = j["password"]
    pin      = j["pin"]
    mobile   = j["mobile"]
    balance  = float(j.get("balance", 0.0))

    if provider not in GRID_PROVIDERS or zone not in GRID_PROVIDERS[provider]:
        return jsonify({"ok": False, "error": "invalid provider/zone"}), 400
    if not (pin.isdigit() and 4 <= len(pin) <= 6):
        return jsonify({"ok": False, "error": "pin must be 4-6 digits"}), 400

    uid = generate_16_digit_id(name, password)
    salt = secrets.token_bytes(16)
    vmid = sha3_hex(f"{uid}|{mobile}".encode())[:20].upper()  # Vehicle Mobile ID
    with state_lock:
        if uid in users:
            return jsonify({"ok": False, "error": "uid collision, retry"}), 500
        users[uid] = {
            "name": name,
            "provider": provider,
            "zone": zone,
            "pin_salt": salt.hex(),
            "pin_hash": hash_pin(pin, salt),
            "mobile": mobile,
            "vmid": vmid,
            "balance": balance,
            "created": time.time(),
        }
        vmid_index[vmid] = uid
        _persist()
    return jsonify({"ok": True, "uid": uid, "vmid": vmid})


@app.route("/authorize_payment", methods=["POST"])
def authorize_payment():
    """
    Called by the Kiosk.
    Expects:
      {
        "vfid_ct_hex": "..."       # ASCON(FID) from QR
        "vfid_nonce_hex": "..."
        "rsa_ct_vmid": [ints...]   # user's VMID encrypted with Grid's RSA pub
        "rsa_ct_pin":  [ints...]
        "amount": 123.45
        "energy_kwh": 6.2
      }
    Returns approved/denied; on approval, records a block.
    """
    j = request.get_json(force=True)
    try:
        vfid_ct = bytes.fromhex(j["vfid_ct_hex"])
        vfid_nonce = bytes.fromhex(j["vfid_nonce_hex"])
        fid_bytes = ascon_decrypt(ASCON_SHARED_KEY, vfid_nonce, vfid_ct, b"EV-KIOSK-VFID")
        fid = fid_bytes.decode("ascii")
    except Exception as e:
        return jsonify({"ok": False, "error": f"VFID decryption failed: {e}"}), 400

    try:
        vmid = rsa_decrypt_bytes(j["rsa_ct_vmid"], RSA_PRIV).decode("ascii")
        pin  = rsa_decrypt_bytes(j["rsa_ct_pin"],  RSA_PRIV).decode("ascii")
    except Exception as e:
        return jsonify({"ok": False, "error": f"RSA decryption failed: {e}"}), 400

    amount     = float(j["amount"])
    energy_kwh = float(j.get("energy_kwh", 0.0))

    with state_lock:
        # Validate franchise
        if fid not in franchises:
            return jsonify({"ok": False, "error": "unknown franchise"}), 404
        franchise = franchises[fid]

        # Validate user via VMID
        uid = vmid_index.get(vmid)
        if uid is None:
            return jsonify({"ok": False, "error": "unknown VMID"}), 404
        user = users[uid]

        # Validate PIN
        salt = bytes.fromhex(user["pin_salt"])
        if hash_pin(pin, salt) != user["pin_hash"]:
            return jsonify({"ok": False, "error": "invalid PIN"}), 401

        # Same zone check (optional policy: users can charge in any zone of same provider)
        if user["provider"] != franchise["provider"]:
            return jsonify({"ok": False, "error": "cross-provider not supported"}), 403

        # Funds check
        if user["balance"] < amount:
            return jsonify({"ok": False, "error": "insufficient balance",
                            "balance": user["balance"]}), 402
        if amount <= 0:
            return jsonify({"ok": False, "error": "amount must be positive"}), 400

        # Transfer funds
        user["balance"]      -= amount
        franchise["balance"] += amount

        # Record block
        block = ledger.add_transaction(uid=uid, fid=fid, amount=amount, energy_kwh=energy_kwh)
        _persist()

    return jsonify({
        "ok": True,
        "tx_id": block.tx_id,
        "block_index": block.index,
        "user_balance_after": user["balance"],
        "franchise_balance_after": franchise["balance"],
        "fid": fid,
        "uid": uid,
    })


@app.route("/reverse_transaction", methods=["POST"])
def reverse_transaction():
    """Called by the Kiosk if hardware failed after a successful payment."""
    j = request.get_json(force=True)
    tx_id  = j["tx_id"]
    reason = j.get("reason", "hardware_failure")
    with state_lock:
        # find original
        original = None
        for b in ledger.chain:
            if b.tx_id == tx_id:
                original = b; break
        if original is None:
            return jsonify({"ok": False, "error": "tx not found"}), 404
        if original.uid not in users or original.fid not in franchises:
            return jsonify({"ok": False, "error": "account closed"}), 409
        # refund
        users[original.uid]["balance"]      += original.amount
        franchises[original.fid]["balance"] -= original.amount
        rev = ledger.add_reverse(tx_id, reason=reason)
        _persist()
    return jsonify({"ok": True, "reverse_tx_id": rev.tx_id, "block_index": rev.index})


@app.route("/chain", methods=["GET"])
def get_chain():
    return jsonify({"length": len(ledger.chain),
                    "valid": ledger.verify(),
                    "chain": ledger.to_list()})


@app.route("/accounts", methods=["GET"])
def get_accounts():
    with state_lock:
        return jsonify({
            "franchises": {k: {kk: vv for kk, vv in v.items() if kk != "password_hash"}
                           for k, v in franchises.items()},
            "users": {k: {"name": v["name"], "provider": v["provider"], "zone": v["zone"],
                         "mobile": v["mobile"], "vmid": v["vmid"], "balance": v["balance"]}
                      for k, v in users.items()},
        })


def run(host="0.0.0.0", port=5000):
    print(f"[grid] Starting Grid Authority on {host}:{port}")
    print(f"[grid] RSA public key (tiny, Shor-breakable): N={RSA_PUB['N']}, e={RSA_PUB['e']}")
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    import argparse
    from common.config import GRID_PORT
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=GRID_PORT)
    args = p.parse_args()
    run(args.host, args.port)
