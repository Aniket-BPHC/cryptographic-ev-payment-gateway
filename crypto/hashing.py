"""
SHA-3 (Keccak-256) helpers.
Used for:
- Generating the 16-digit Franchise ID (FID) and User ID (UID)
- Hashing PINs (never store plaintext PIN)
- Transaction IDs in the blockchain
- Block hash linking
"""
import hashlib
import time


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha3_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def generate_16_digit_id(name: str, password: str, timestamp: float = None) -> str:
    """
    Generate a 16-digit hexadecimal ID from name + timestamp + password using SHA-3-256.
    Used for both Franchise IDs (FID) and User IDs (UID) per the spec.
    """
    if timestamp is None:
        timestamp = time.time()
    raw = f"{name}|{timestamp}|{password}".encode("utf-8")
    digest = sha3_hex(raw)
    # Take first 16 hex chars = 64 bits = "16-digit hexadecimal number"
    return digest[:16].upper()


def hash_pin(pin: str, salt: bytes) -> str:
    """Hash a PIN with a per-user salt. Never store plaintext PIN."""
    return sha3_hex(salt + pin.encode("utf-8"))


def hash_transaction(uid: str, fid: str, timestamp: float, amount: float) -> str:
    """Transaction ID = SHA-3(UID || FID || timestamp || amount)."""
    raw = f"{uid}|{fid}|{timestamp}|{amount}".encode("utf-8")
    return sha3_hex(raw)


if __name__ == "__main__":
    fid = generate_16_digit_id("TataPower-Hyd-01", "secret123")
    print("Sample FID:", fid, "len=", len(fid))
    assert len(fid) == 16
    print("SHA-3 helpers OK")
