import hashlib
import random
import time

def miller_rabin(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    even_num = n - 1
    r = 0
    while even_num % 2 == 0:
        even_num //= 2
        r += 1
    d = even_num

    for _ in range(rounds):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True



def generate_prime(bit_length: int) -> int:
    while True:
        candidate = random.getrandbits(bit_length) | (1 << (bit_length - 1)) | 1
        if miller_rabin(candidate):
            return candidate
    


def find_generator(P: int) -> int:
    candidate = random.randint(2, P - 2)
    q = (P - 1) // 2  
    while pow(candidate, 2, P) == 1 or pow(candidate, q, P) == 1:
        candidate = random.randint(2, P - 2)
    return candidate


def derive_aes_key(shared_secret: int, key_bits: int) -> bytes:
    return hashlib.sha256(str(shared_secret).encode()).digest()[:key_bits // 8]

def generate_public_parameters(bit_length: int, seed=42):
    if seed is not None:
        random.seed(seed)
    P = generate_prime(bit_length)
    g = find_generator(P)
    return P, g


def generate_private_public_pair(P: int, g: int, bit_length: int):
    private = random.getrandbits(bit_length) | (1 << (bit_length - 1))
    public = pow(g, private, P)
    return private, public


def compute_shared_secret(their_public: int, own_private: int, P: int) -> int:
    return pow(their_public, own_private, P)

def run_trial(bit_length: int):
    t0 = time.perf_counter()
    P, g = generate_public_parameters(bit_length)
    t1 = time.perf_counter()

    Ka, A = generate_private_public_pair(P, g, bit_length)
    t2 = time.perf_counter()

    Kb, B = generate_private_public_pair(P, g, bit_length)
    t3 = time.perf_counter()

    s_alice = compute_shared_secret(B, Ka, P)
    s_bob = compute_shared_secret(A, Kb, P)
    t4 = time.perf_counter()

    assert s_alice == s_bob, "Alice and Bob disagree on the shared secret!"

    return {
        "P": P, "g": g, "A": A, "B": B, "s": s_alice,
        "time_params_ms": (t1 - t0) * 1000,  # generating P, g (not in the table, but handy)
        "time_A_ms": (t2 - t1) * 1000,       # Alice's keypair
        "time_B_ms": (t3 - t2) * 1000,       # Bob's keypair
        "time_s_ms": (t4 - t3) * 1000,       # both sides computing s
    }


def report(bit_lengths=(128, 192, 256), trials: int = 5):
    print(f"{'k':>4} | {'A (ms)':>12} | {'B (ms)':>12} | {'shared key s (ms)':>18}")
    print("-" * 56)
    for k in bit_lengths:
        totals = {"time_A_ms": 0.0, "time_B_ms": 0.0, "time_s_ms": 0.0}
        for _ in range(trials):
            result = run_trial(k)
            for key in totals:
                totals[key] += result[key]
        avg = {key: val / trials for key, val in totals.items()}
        print(f"{k:>4} | {avg['time_A_ms']:>12.4f} | {avg['time_B_ms']:>12.4f} "
              f"| {avg['time_s_ms']:>18.4f}")


if __name__ == "__main__":
    report()
