"""
Centralized blockchain ledger maintained by the Grid Authority.

Block structure (per spec Section 6):
  - transaction_id : SHA-3(UID || FID || timestamp || amount)
  - previous_hash  : SHA-3 of the previous block's full serialization
  - timestamp      : float (unix)
  - dispute_flag   : bool  (set True by reverse/refund blocks)
  - reverses       : optional tx_id of a prior block this one reverses
  - uid, fid, amount, energy_kwh : transaction payload
"""
import json
import time
from threading import Lock
from crypto.hashing import sha3_hex, hash_transaction


class Block:
    def __init__(self, index, uid, fid, amount, energy_kwh,
                 previous_hash, timestamp=None, dispute_flag=False,
                 reverses=None, tx_id=None):
        self.index = index
        self.uid = uid
        self.fid = fid
        self.amount = amount
        self.energy_kwh = energy_kwh
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.previous_hash = previous_hash
        self.dispute_flag = dispute_flag
        self.reverses = reverses  # tx_id of block being reversed, or None
        self.tx_id = tx_id or hash_transaction(uid, fid, self.timestamp, amount)

    def to_dict(self):
        return {
            "index": self.index,
            "tx_id": self.tx_id,
            "uid": self.uid,
            "fid": self.fid,
            "amount": self.amount,
            "energy_kwh": self.energy_kwh,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "dispute_flag": self.dispute_flag,
            "reverses": self.reverses,
        }

    def block_hash(self):
        return sha3_hex(json.dumps(self.to_dict(), sort_keys=True).encode("utf-8"))


class Blockchain:
    def __init__(self):
        self.chain = []
        self._lock = Lock()
        # Genesis block
        genesis = Block(
            index=0, uid="GENESIS", fid="GENESIS",
            amount=0.0, energy_kwh=0.0,
            previous_hash="0" * 64,
            timestamp=0.0,
            tx_id="GENESIS",
        )
        self.chain.append(genesis)

    def add_transaction(self, uid, fid, amount, energy_kwh,
                        dispute_flag=False, reverses=None) -> Block:
        with self._lock:
            prev = self.chain[-1]
            block = Block(
                index=len(self.chain),
                uid=uid, fid=fid, amount=amount, energy_kwh=energy_kwh,
                previous_hash=prev.block_hash(),
                dispute_flag=dispute_flag,
                reverses=reverses,
            )
            self.chain.append(block)
            return block

    def add_reverse(self, original_tx_id, reason="hardware_failure") -> Block:
        """Add a reverse/refund block that undoes a prior transaction."""
        original = None
        for b in self.chain:
            if b.tx_id == original_tx_id:
                original = b
                break
        if original is None:
            raise ValueError(f"Original tx {original_tx_id} not found")
        return self.add_transaction(
            uid=original.uid, fid=original.fid,
            amount=-original.amount, energy_kwh=-original.energy_kwh,
            dispute_flag=True, reverses=original_tx_id,
        )

    def verify(self) -> bool:
        """Re-hash every block and check the chain is unbroken."""
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i - 1].block_hash():
                return False
        return True

    def to_list(self):
        return [b.to_dict() for b in self.chain]

    def pretty_print(self):
        for b in self.chain:
            flag = " [DISPUTE/REVERSE]" if b.dispute_flag else ""
            print(f"  Block #{b.index}{flag}")
            print(f"    tx_id       : {b.tx_id}")
            print(f"    uid         : {b.uid}")
            print(f"    fid         : {b.fid}")
            print(f"    amount      : {b.amount}")
            print(f"    energy (kWh): {b.energy_kwh}")
            print(f"    prev_hash   : {b.previous_hash[:16]}...")
            if b.reverses:
                print(f"    reverses    : {b.reverses}")


if __name__ == "__main__":
    bc = Blockchain()
    bc.add_transaction("UID1", "FID1", 100.0, 5.5)
    bc.add_transaction("UID2", "FID1", 250.0, 13.2)
    b = bc.add_transaction("UID1", "FID2", 50.0, 2.8)
    bc.add_reverse(b.tx_id, "hardware_failure")
    bc.pretty_print()
    assert bc.verify()
    print("Blockchain OK")
