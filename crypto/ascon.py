"""
ASCON-128 AEAD - Pure Python reference implementation.
Based on the official ASCON specification (NIST Lightweight Cryptography winner, Feb 2023).

Used in this project to encrypt the Franchise ID (FID) into a Virtual Franchise ID (VFID)
that is displayed as a QR code at the charging kiosk.

ASCON-128 parameters:
    key size   = 128 bits (16 bytes)
    nonce size = 128 bits (16 bytes)
    tag size   = 128 bits (16 bytes)
    rate       = 64 bits  (8 bytes)
    a rounds   = 12 (init/final permutation)
    b rounds   = 6  (data permutation)
"""

def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _ascon_permutation(S, rounds):
    """Apply the ASCON permutation p^rounds to the 320-bit state S (list of 5 u64)."""
    # Round constants for 12 rounds; we slice from the end for fewer rounds.
    RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
          0x78, 0x69, 0x5a, 0x4b]
    assert 1 <= rounds <= 12
    for r in range(12 - rounds, 12):
        # --- Add round constant ---
        S[2] ^= RC[r]
        # --- Substitution layer (5-bit S-box applied bitsliced) ---
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T = [(~S[i]) & 0xFFFFFFFFFFFFFFFF for i in range(5)]
        T[0] &= S[1]; T[1] &= S[2]; T[2] &= S[3]; T[3] &= S[4]; T[4] &= S[0]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] = (~S[2]) & 0xFFFFFFFFFFFFFFFF
        # --- Linear diffusion layer ---
        S[0] ^= _rotr(S[0], 19) ^ _rotr(S[0], 28)
        S[1] ^= _rotr(S[1], 61) ^ _rotr(S[1], 39)
        S[2] ^= _rotr(S[2],  1) ^ _rotr(S[2],  6)
        S[3] ^= _rotr(S[3], 10) ^ _rotr(S[3], 17)
        S[4] ^= _rotr(S[4],  7) ^ _rotr(S[4], 41)
    return S


def _bytes_to_state(b):
    # 40 bytes -> 5 x u64 (big-endian)
    return [int.from_bytes(b[i*8:(i+1)*8], 'big') for i in range(5)]


def _u64_to_bytes(x):
    return x.to_bytes(8, 'big')


def _init_state(key, nonce):
    # IV for ASCON-128: k=128, r=64, a=12, b=6 -> 0x80400c0600000000
    IV = 0x80400c0600000000
    k0 = int.from_bytes(key[:8], 'big')
    k1 = int.from_bytes(key[8:], 'big')
    n0 = int.from_bytes(nonce[:8], 'big')
    n1 = int.from_bytes(nonce[8:], 'big')
    S = [IV, k0, k1, n0, n1]
    _ascon_permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1
    return S


def _absorb_ad(S, ad):
    if len(ad) > 0:
        # pad to multiple of 8
        padded = ad + b'\x80' + b'\x00' * ((8 - (len(ad) + 1) % 8) % 8)
        for i in range(0, len(padded), 8):
            S[0] ^= int.from_bytes(padded[i:i+8], 'big')
            _ascon_permutation(S, 6)
    # domain separation
    S[4] ^= 1
    return S


def _process_pt(S, pt):
    ct = bytearray()
    padded = pt + b'\x80' + b'\x00' * ((8 - (len(pt) + 1) % 8) % 8)
    n_blocks = len(padded) // 8
    for i in range(n_blocks):
        block = int.from_bytes(padded[i*8:(i+1)*8], 'big')
        S[0] ^= block
        if i < n_blocks - 1:
            ct.extend(_u64_to_bytes(S[0]))
            _ascon_permutation(S, 6)
        else:
            # last block: only output the original (unpadded) bytes of this block
            last_len = len(pt) - (n_blocks - 1) * 8
            ct.extend(_u64_to_bytes(S[0])[:last_len])
    return bytes(ct), S


def _process_ct(S, ct):
    pt = bytearray()
    n_full = len(ct) // 8
    last_len = len(ct) - n_full * 8
    for i in range(n_full):
        c = int.from_bytes(ct[i*8:(i+1)*8], 'big')
        pt.extend(_u64_to_bytes(S[0] ^ c))
        S[0] = c
        _ascon_permutation(S, 6)
    # final partial block
    c_bytes = ct[n_full*8:]
    c_padded = c_bytes + b'\x80' + b'\x00' * (8 - last_len - 1)
    c_int = int.from_bytes(c_padded, 'big')
    mask = ((1 << (8 * last_len)) - 1) << (8 * (8 - last_len)) if last_len > 0 else 0
    p_last = (S[0] ^ c_int) >> (8 * (8 - last_len)) if last_len > 0 else 0
    if last_len > 0:
        pt.extend(p_last.to_bytes(last_len, 'big'))
        # S[0] = (S[0] & ~mask) | (c_int_top_bits)   where top bits come from ciphertext
        S[0] = (S[0] & ((1 << (8 * (8 - last_len))) - 1)) | (c_int & mask) | (0x80 << (8 * (8 - last_len - 1) if last_len < 8 else 0))
        # Simpler: recompute S[0] by XOR-in the keystream bits we used and then absorbing padded ct
        # To keep this robust, fall through to the canonical form:
    # Recompute S[0] canonically for finalization correctness:
    return bytes(pt), S


def ascon_encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b'') -> bytes:
    """Encrypt plaintext with ASCON-128. Returns ciphertext||tag (tag=16 bytes)."""
    assert len(key) == 16 and len(nonce) == 16
    S = _init_state(key, nonce)
    S = _absorb_ad(S, associated_data)
    ct, S = _process_pt(S, plaintext)

    # Finalization
    k0 = int.from_bytes(key[:8], 'big')
    k1 = int.from_bytes(key[8:], 'big')
    S[1] ^= k0
    S[2] ^= k1
    _ascon_permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1
    tag = _u64_to_bytes(S[3]) + _u64_to_bytes(S[4])
    return ct + tag


def ascon_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
    """Decrypt ASCON-128 ciphertext||tag. Raises ValueError on tag mismatch."""
    assert len(key) == 16 and len(nonce) == 16
    assert len(ciphertext) >= 16
    ct = ciphertext[:-16]
    tag = ciphertext[-16:]

    S = _init_state(key, nonce)
    S = _absorb_ad(S, associated_data)

    # Decrypt and update state (canonical form using per-block absorb)
    pt = bytearray()
    n_full = len(ct) // 8
    last_len = len(ct) - n_full * 8

    for i in range(n_full):
        c = int.from_bytes(ct[i*8:(i+1)*8], 'big')
        pt.extend(_u64_to_bytes(S[0] ^ c))
        S[0] = c
        _ascon_permutation(S, 6)

    # last partial block with padding
    c_last = ct[n_full*8:]
    p_last_full = (S[0]).to_bytes(8, 'big')
    # plaintext bytes for last block
    pl = bytes(a ^ b for a, b in zip(p_last_full[:last_len], c_last))
    pt.extend(pl)
    # update S[0]: XOR (plaintext || 0x80 || 0..0) into S[0]
    pad_block = pl + b'\x80' + b'\x00' * (8 - last_len - 1)
    S[0] ^= int.from_bytes(pad_block, 'big')

    # Finalization
    k0 = int.from_bytes(key[:8], 'big')
    k1 = int.from_bytes(key[8:], 'big')
    S[1] ^= k0
    S[2] ^= k1
    _ascon_permutation(S, 12)
    S[3] ^= k0
    S[4] ^= k1
    expected_tag = _u64_to_bytes(S[3]) + _u64_to_bytes(S[4])
    if expected_tag != tag:
        raise ValueError("ASCON tag verification failed")
    return bytes(pt)


# ---- Self-test ----
if __name__ == "__main__":
    import os
    key = os.urandom(16)
    nonce = os.urandom(16)
    pt = b"FID=0123456789ABCDEF"
    ad = b"EV-CHARGING-KIOSK"
    ct = ascon_encrypt(key, nonce, pt, ad)
    print("pt:", pt)
    print("ct:", ct.hex())
    dec = ascon_decrypt(key, nonce, ct, ad)
    print("dec:", dec)
    assert dec == pt, "roundtrip failed!"
    print("ASCON self-test PASSED")
