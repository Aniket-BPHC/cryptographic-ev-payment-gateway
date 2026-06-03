"""
Shared configuration. Override via environment variables to deploy on 3 machines.
"""
import os

GRID_HOST = os.environ.get("GRID_HOST", "127.0.0.1")
GRID_PORT = int(os.environ.get("GRID_PORT", "5000"))
GRID_URL  = f"http://{GRID_HOST}:{GRID_PORT}"

KIOSK_HOST = os.environ.get("KIOSK_HOST", "127.0.0.1")
KIOSK_PORT = int(os.environ.get("KIOSK_PORT", "5001"))
KIOSK_URL  = f"http://{KIOSK_HOST}:{KIOSK_PORT}"

# Shared symmetric key for ASCON (VFID encryption).
# In a real deployment this would be provisioned via a KMS; here, both the Kiosk
# and the Grid know it so the Grid can decrypt the VFID from the QR.
ASCON_SHARED_KEY = bytes.fromhex(
    os.environ.get("ASCON_KEY", "0123456789abcdef" * 2)
)
assert len(ASCON_SHARED_KEY) == 16

# Grid providers and zones
GRID_PROVIDERS = {
    "TATA":      ["TATA-Z01", "TATA-Z02", "TATA-Z03"],
    "ADANI":     ["ADANI-Z01", "ADANI-Z02", "ADANI-Z03"],
    "CHARGEPT":  ["CHGP-Z01", "CHGP-Z02", "CHGP-Z03"],
}

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(DATA_DIR, exist_ok=True)
