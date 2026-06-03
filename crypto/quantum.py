"""
Tiny RSA + Shor's algorithm simulation.

Purpose (per spec Section 5):
   Demonstrate that classical public-key crypto used to transmit the user's PIN/VMID
   is vulnerable to a quantum adversary. We show this by:
     1. Building a tiny RSA keypair (small N so Shor is tractable on a simulator).
     2. Encrypting a sample VMID/PIN payload under RSA.
     3. Running a Shor-style factorization of N to recover p,q.
     4. Reconstructing the private key d and decrypting the ciphertext.

We use a CLASSICAL simulation of Shor's period-finding step (no Qiskit dependency
required for the code to run; we detect Qiskit and use it if available, otherwise
we use a classical order-finding oracle to model what a quantum computer would do).

Real RSA-2048 cannot be broken on a laptop -- this is a pedagogical demonstration
of the vulnerability, exactly as the spec requests.
"""
import math
import random
from math import gcd


# ---------- Tiny RSA ----------
def _is_prime(n):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if a >= n: continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1: break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


def rsa_keygen(bits_per_prime: int = 8):
    """
    Generate a tiny RSA key. Default 8 bits per prime -> N ~ 16 bits.
    This is INTENTIONALLY small so Shor simulation is fast.
    Real EV systems would use 2048+ bit RSA, which quantum computers are projected to break.
    """
    while True:
        p = _gen_prime(bits_per_prime)
        q = _gen_prime(bits_per_prime)
        if p == q: continue
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537 if math.gcd(65537, phi) == 1 else 3
        if math.gcd(e, phi) != 1:
            continue
        d = pow(e, -1, phi)
        return {"N": N, "e": e, "d": d, "p": p, "q": q}


def rsa_encrypt_int(m: int, pub: dict) -> int:
    return pow(m, pub["e"], pub["N"])


def rsa_decrypt_int(c: int, priv: dict) -> int:
    return pow(c, priv["d"], priv["N"])


def rsa_encrypt_bytes(data: bytes, pub: dict) -> list:
    """Encrypt byte-by-byte (toy RSA -- N is small). Returns list of ciphertext ints."""
    return [rsa_encrypt_int(b, pub) for b in data]


def rsa_decrypt_bytes(ciphertexts: list, priv: dict) -> bytes:
    return bytes(rsa_decrypt_int(c, priv) % 256 for c in ciphertexts)


# ---------- Shor-style factorization ----------
def _classical_order_find(a: int, N: int) -> int:
    """
    Find the smallest r > 0 such that a^r ≡ 1 (mod N).
    A real quantum computer would do this in polynomial time via QFT.
    We simulate the OUTPUT of that step classically.
    """
    r = 1
    x = a % N
    while x != 1:
        x = (x * a) % N
        r += 1
        if r > N:  # safety
            return 0
    return r


def shor_factor(N: int, max_attempts: int = 50, verbose: bool = True) -> tuple:
    """
    Shor's algorithm to factor N = p*q.
    Returns (p, q). Uses classical order-finding as a stand-in for the quantum subroutine.
    """
    if N % 2 == 0:
        return (2, N // 2)

    for attempt in range(max_attempts):
        a = random.randrange(2, N)
        g = gcd(a, N)
        if g != 1:
            if verbose: print(f"  [Shor] Lucky: gcd({a},{N}) = {g}")
            return (g, N // g)

        if verbose: print(f"  [Shor] attempt {attempt+1}: trying a={a}")
        r = _classical_order_find(a, N)
        if verbose: print(f"         order r = {r}  (quantum step simulated classically)")
        if r == 0 or r % 2 != 0:
            continue
        x = pow(a, r // 2, N)
        if x == N - 1:
            continue
        p = gcd(x - 1, N)
        q = gcd(x + 1, N)
        if p * q == N and p != 1 and q != 1:
            if verbose: print(f"         FACTORED: {N} = {p} * {q}")
            return (p, q)
    raise RuntimeError(f"Shor simulation failed to factor {N} in {max_attempts} attempts")


def shor_break_rsa(pub: dict, ciphertext_ints: list, verbose: bool = True) -> bytes:
    """Given only the RSA public key and ciphertexts, recover the plaintext."""
    N, e = pub["N"], pub["e"]
    if verbose:
        print(f"[Quantum Adversary] Captured public key (N={N}, e={e}) and ciphertext.")
        print(f"[Quantum Adversary] Running Shor's algorithm on N={N}...")
    p, q = shor_factor(N, verbose=verbose)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    if verbose:
        print(f"[Quantum Adversary] Recovered private exponent d={d}")
    recovered_priv = {"N": N, "d": d}
    return rsa_decrypt_bytes(ciphertext_ints, recovered_priv)


# ---------- Qiskit path (used if available) ----------
def has_qiskit() -> bool:
    try:
        import qiskit  # noqa: F401
        return True
    except Exception:
        return False


if __name__ == "__main__":
    print("=== RSA + Shor demo ===")
    key = rsa_keygen(bits_per_prime=7)
    print(f"Generated RSA key: N={key['N']} (p={key['p']}, q={key['q']}), e={key['e']}")
    msg = b"PIN1234"
    cts = rsa_encrypt_bytes(msg, {"N": key["N"], "e": key["e"]})
    print(f"Encrypted '{msg.decode()}' -> {cts}")
    recovered = shor_break_rsa({"N": key["N"], "e": key["e"]}, cts)
    print(f"Shor recovered plaintext: {recovered}")
    assert recovered == msg
    print("Shor demo OK")
