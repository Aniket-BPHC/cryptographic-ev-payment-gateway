# Secure EV Charging Payment Gateway
### Cryptography Term Project (BITS F463) — 2025-26

A simulation of a secure EV charging payment system combining:

- **ASCON-128** (NIST lightweight cryptography winner) — encrypts the Franchise ID
  into a Virtual Franchise ID (VFID) shown as a QR code at the kiosk.
- **SHA-3 / Keccak-256** — generates the 16-digit Franchise ID (FID) and User ID
  (UID), hashes PINs (with per-user salt), and produces transaction IDs.
- **RSA (intentionally tiny)** — carries the user's VMID and PIN end-to-end from
  the user device through the kiosk to the Grid, so the kiosk cannot see them.
- **Shor's Algorithm (simulated)** — demonstrates that the RSA layer is
  quantum-vulnerable by recovering a PIN from captured ciphertext + public key.
- **Centralized Blockchain Ledger** — immutable, hash-linked record of every
  charging transaction, including dispute/reverse blocks for hardware failures.

---

## Architecture

```
 ┌──────────────────┐     HTTP      ┌──────────────────┐     HTTP      ┌──────────────────┐
 │   User Device    │ ───────────▶  │  Charging Kiosk  │ ───────────▶  │  Grid Authority  │
 │   (EV Owner)     │   /pay        │  (relay, QR)     │ /authorize_…  │ (ledger, accts)  │
 └──────────────────┘               └──────────────────┘               └──────────────────┘
        │                                   │                                    │
        │ RSA(pub) encrypt ─ VMID, PIN ─────┼──────────── forward ──────────────▶│ RSA priv
        │ scans QR ─ ASCON(FID)  ───────────┘                                    │ ASCON key (shared)
```

Three independent Flask/CLI processes. Default ports:

| Component       | Port (default) | Launch command                          |
|-----------------|----------------|-----------------------------------------|
| Grid Authority  | 5000           | `python3 -m grid.server`                |
| Charging Kiosk  | 5001           | `python3 -m kiosk.server`               |
| User CLI        | —              | `python3 -m user_device.client …`       |
| Franchise CLI   | —              | `python3 -m franchise.cli …`            |

To deploy on three physical devices, set these environment variables on the
machine that needs to reach the others:

```bash
export GRID_HOST=192.168.1.10
export KIOSK_HOST=192.168.1.11
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

Requires Python 3.9+. No external crypto libraries are needed — ASCON, SHA-3,
RSA, and Shor are all implemented from first principles (SHA-3 via `hashlib`).

### 2. Run the fully-automated end-to-end demo (recommended first)

```bash
python3 -m demo.auto_demo
```

This starts both servers in background threads and exercises the entire flow:
registration, QR scan, happy-path payment, wrong-PIN rejection, insufficient-
balance rejection, cross-provider rejection, hardware-failure reverse block,
blockchain audit, and finally the Shor attack recovering a captured PIN.

### 3. Manual / interactive mode

Terminal 1 — start both servers:
```bash
./run_all.sh              # Linux/Mac
# or manually:
python3 -m grid.server   &
python3 -m kiosk.server  &
```

Terminal 2 — onboarding:
```bash
python3 -m franchise.cli register      # creates FID, prints it
python3 -m franchise.cli boot          # enter the FID to bring kiosk online
python3 -m user_device.client register # creates UID + VMID, prints them
```

Terminal 2 — charging session:
```bash
python3 -m user_device.client charge
# enter VMID, PIN, amount, energy
```

Stop servers: `./stop_all.sh`

---

## Project Layout

```
ev_project/
├── crypto/
│   ├── ascon.py         # ASCON-128 AEAD (pure Python, self-test included)
│   ├── hashing.py       # SHA-3 helpers: FID/UID gen, PIN hashing, tx IDs
│   └── quantum.py       # Tiny RSA + Shor's algorithm simulation
├── blockchain/
│   └── ledger.py        # Block + Blockchain (genesis, add, reverse, verify)
├── grid/
│   └── server.py        # Grid Authority Flask server
├── kiosk/
│   └── server.py        # Charging Kiosk Flask server
├── user_device/
│   └── client.py        # EV Owner CLI (register, charge)
├── franchise/
│   └── cli.py           # Franchise CLI (register, boot kiosk)
├── common/
│   └── config.py        # Shared config (ports, ASCON key, provider list)
├── demo/
│   └── auto_demo.py     # End-to-end automated demo
├── data/                # Runtime logs + persisted grid state (JSON snapshot)
├── run_all.sh           # Launcher (Linux/Mac)
├── stop_all.sh
├── requirements.txt
└── README.md
```

---

## Cryptographic Details

### ASCON-128 (Lightweight Cryptography)
- **Where:** The kiosk encrypts its 16-character FID to produce the VFID
  displayed in the QR code. The Grid (which shares the ASCON key) decrypts it.
- **Why:** ASCON is NIST's selected lightweight AEAD standard (Feb 2023),
  designed for low-power / IoT devices such as charging kiosks and vehicle
  communication modules.
- **Params:** 128-bit key, 128-bit nonce, 128-bit tag, rate 64, a=12, b=6.
- **Freshness:** A new random nonce is generated on every `/qr` fetch, so the
  QR changes each scan — this prevents replay of a captured QR image.
- **Integrity:** The 128-bit tag authenticates both the ciphertext and the
  `"EV-KIOSK-VFID"` associated-data tag. Tampering is detected on decrypt.

### SHA-3 / Keccak-256
- **FID generation:** `SHA3-256(name || timestamp || password)`, truncated to 16
  hex chars (64 bits) — matching the spec's "16-digit hexadecimal number".
- **UID generation:** same scheme for EV owners.
- **VMID:** `SHA3-256(UID || mobile)` → first 20 hex chars.
- **PIN storage:** `SHA3-256(salt || pin)` with a 128-bit per-user salt. The
  plaintext PIN is never stored or logged.
- **Transaction ID:** `SHA3-256(UID || FID || timestamp || amount)`.
- **Block hash:** `SHA3-256` of the block's canonical JSON serialization; each
  block stores the previous block's hash → tamper-evident chain.

### RSA + Shor's Algorithm
- **Where:** The user device fetches the Grid's RSA public key and encrypts the
  VMID and PIN **end-to-end** — the kiosk sees only ciphertext and forwards it.
- **Why tiny:** RSA-2048 is infeasible to factor on a simulator, so we use
  ~14-bit moduli (two 7-bit primes). This is explicitly pedagogical, per the
  project spec.
- **Shor simulation:** Implemented classically because Qiskit isn't required for
  a working simulator. The period-finding step — the part a quantum computer
  accelerates — is replaced by a classical order-finding oracle. The surrounding
  Shor protocol (pick random `a`, check `gcd(a,N)`, find order `r`, use
  `gcd(a^(r/2) ± 1, N)`) is implemented exactly as a real quantum attacker
  would use it.
- **Attack demo:** `demo/auto_demo.py` step 10 shows an eavesdropper capturing
  only `(N, e)` and a ciphertext, running Shor, and recovering the plaintext
  PIN — the exact scenario that justifies post-quantum migration.

### Centralized Blockchain
- Maintained in-memory by the Grid; snapshotted to `data/grid_state.json` after
  every write for inspection.
- **Block fields:** `index`, `tx_id`, `uid`, `fid`, `amount`, `energy_kwh`,
  `timestamp`, `previous_hash`, `dispute_flag`, `reverses` (tx_id being undone).
- **Reverse blocks:** Have negative `amount` / `energy_kwh` and
  `dispute_flag=True`. The original block is preserved (immutability); the
  reverse is appended and also refunds the user / debits the franchise.
- **Verification:** `GET /chain` returns `valid=True/False` by re-hashing every
  block.

---

## Edge Cases Handled (documented assumptions)

| Situation                                  | Behavior                                                                 |
|--------------------------------------------|--------------------------------------------------------------------------|
| Wrong PIN                                  | HTTP 401, no balance change, no block created                            |
| Unknown VMID                               | HTTP 404, no block                                                       |
| Unknown FID (VFID decrypts to bad data)    | HTTP 400, no block                                                       |
| Insufficient balance                       | HTTP 402, no block; balance returned in response                         |
| Cross-provider charging                    | HTTP 403 (user must use same provider as franchise)                      |
| Non-positive amount                        | HTTP 400                                                                 |
| VFID tampering / wrong ASCON key           | HTTP 400 (ASCON tag verification fails)                                  |
| Replay of old QR                           | Kiosk refreshes nonce on each `/qr`; Grid accepts any valid VFID but the user's RSA-encrypted PIN is also bound to this session, limiting replay value |
| Hardware failure after approval            | Kiosk calls `/reverse_transaction` → Grid appends dispute block, refunds user, debits franchise |
| Account closed mid-session (after payment) | Reverse-transaction endpoint returns HTTP 409 if either side no longer exists |
| Concurrent requests                        | Grid uses a `threading.Lock` around account + ledger mutation            |
| Kiosk not booted with FID                  | `/qr` and `/pay` return HTTP 409                                         |

**Unhandled (out of scope):** persistent storage across restarts (state is
in-memory + JSON snapshot for inspection only); TLS between services (assumed
provided by a network layer in deployment); denial-of-service protections.

---

## How Each Spec Requirement Maps to the Code

| Spec (Section)                               | Implementation                                                       |
|----------------------------------------------|----------------------------------------------------------------------|
| 3 providers × 3 zones (§2)                   | `common/config.py` → `GRID_PROVIDERS`                                |
| Franchise registration → 16-digit FID (§2)   | `grid/server.py::register_franchise` + `crypto/hashing.py`           |
| User registration with PIN + VMID (§2)       | `grid/server.py::register_user`                                      |
| QR with encrypted FID (§2)                   | `kiosk/server.py::qr` + `crypto/ascon.py`                            |
| User provides VMID+amount+PIN (§2)           | `user_device/client.py::charge_interactive`                          |
| Kiosk decrypts VFID → forwards to Grid (§2)  | `kiosk/server.py::pay` + `grid/server.py::authorize_payment`         |
| Grid validates funds/VMID/PIN (§2)           | `grid/server.py::authorize_payment`                                  |
| Blockchain records valid transaction (§6)    | `blockchain/ledger.py::add_transaction`                              |
| Funds transferred to franchise (§2)          | `grid/server.py::authorize_payment`                                  |
| ASCON for LWC (§4)                           | `crypto/ascon.py`                                                    |
| Shor breaking RSA (§5)                       | `crypto/quantum.py::shor_break_rsa`                                  |
| Block fields: tx_id, prev_hash, ts, flag (§6)| `blockchain/ledger.py::Block`                                        |
| Reverse block on hardware failure (§6)       | `kiosk/server.py::simulate_fail` + `grid/server.py::reverse_transaction` |

---

## Running the Unit Self-Tests

Each crypto module has a `__main__` self-test:

```bash
python3 -m crypto.ascon        # ASCON roundtrip
python3 -m crypto.hashing      # FID generation
python3 -m crypto.quantum      # RSA keygen + Shor factorization
python3 -m blockchain.ledger   # Chain with reverse block + verify()
```

---

## Team

BITS F463 — Cryptography Term Project 2025-26
