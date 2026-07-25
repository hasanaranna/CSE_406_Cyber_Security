import os
import time

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

BLOCK_SIZE = 16   
NUM_ROUNDS = 10   


def to_hex_str(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)

def to_ascii_str(data: bytes) -> str:
    return data.decode('latin-1')

class Timer:
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000
        return False  # don't swallow exceptions

def bytes_to_state(block: bytes):
    assert len(block) == 16
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]

def state_to_bytes(state) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            value = state[r][c]
            col = value & 0x0F
            row = (value >> 4) & 0x0F
            state[r][c] = Sbox[row * 16 + col]
    return state

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            value = state[r][c]
            col = value & 0x0F
            row = (value >> 4) & 0x0F
            state[r][c] = InvSbox[row * 16 + col]
    return state

def shift_rows(state):
    for r in range(4):
        state[r] = state[r][r:] + state[r][:r]
    return state

def inv_shift_rows(state):
    for r in range(4):
        state[r] = state[r][-r:] + state[r][:-r]
    return state

def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_col = []
        for r in range(4):
            value = (gf_mult(Mixer[r][0], col[0]) ^
                     gf_mult(Mixer[r][1], col[1]) ^
                     gf_mult(Mixer[r][2], col[2]) ^
                     gf_mult(Mixer[r][3], col[3]))
            new_col.append(value)
        for r in range(4):
            state[r][c] = new_col[r]
    return state

def inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_col = []
        for r in range(4):
            value = (gf_mult(InvMixer[r][0], col[0]) ^
                     gf_mult(InvMixer[r][1], col[1]) ^
                     gf_mult(InvMixer[r][2], col[2]) ^
                     gf_mult(InvMixer[r][3], col[3]))
            new_col.append(value)
        for r in range(4):
            state[r][c] = new_col[r]
    return state

def add_round_key(state, round_key_block: bytes):
    round_key_state = bytes_to_state(round_key_block)
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key_state[r][c]
    return state

def normalize_key_to_16_bytes(key: bytes) -> bytes:
    if len(key) == 16:
        return key
    
    if len(key) < 16:
        return key.ljust(16, b'\x00')
    
    return key[:16]

def key_expansion(key: bytes):
    words = [key[i:i+4] for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i-1]
        
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = bytes([Sbox[b] for b in temp])
            rcon_word = bytes([Rcon[i // 4], 0x00, 0x00, 0x00])
            temp = bytes([b1 ^ b2 for b1, b2 in zip(temp, rcon_word)])
            
        new_word = bytes([b1 ^ b2 for b1, b2 in zip(temp, words[i-4])])
        words.append(new_word)

    round_keys = []
    for i in range(0, 44, 4):
        round_key = b''.join(words[i:i+4])
        round_keys.append(round_key)
    return round_keys

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding
    
def pkcs7_unpad(data: bytes) -> bytes:
    N = data[-1]
    return data[:-N]

def aes_encrypt_block(plaintext_block: bytes, round_keys) -> bytes:
    state = bytes_to_state(plaintext_block)
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, NUM_ROUNDS):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    # Final round has no mixColumns 
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[NUM_ROUNDS])
    return state_to_bytes(state)


def aes_decrypt_block(ciphertext_block: bytes, round_keys) -> bytes:
    state = bytes_to_state(ciphertext_block)
    state = add_round_key(state, round_keys[NUM_ROUNDS])
    for rnd in range(NUM_ROUNDS - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)

def ecb_encrypt(plaintext: bytes, round_keys) -> bytes:
    padded_plaintext = pkcs7_pad(plaintext)
    blocks = [padded_plaintext[i:i+16] for i in range(0, len(padded_plaintext), 16)]
    return b''.join(aes_encrypt_block(block, round_keys) for block in blocks)

def ecb_decrypt(ciphertext: bytes, round_keys) -> bytes:
    split_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_blocks = [aes_decrypt_block(block, round_keys) for block in split_blocks]
    return b''.join(decrypted_blocks)

def cbc_encrypt(plaintext: bytes, round_keys) -> bytes:
    IV = os.urandom(16)
    padded_plaintext = pkcs7_pad(plaintext)
    blocks = [padded_plaintext[i:i+16] for i in range(0, len(padded_plaintext), 16)]
    previous = IV
    ciphertext = bytearray()
    for block in blocks:
        x = bytes(b1 ^ b2 for b1, b2 in zip(block, previous))
        c = aes_encrypt_block(x, round_keys)
        ciphertext.extend(c)
        previous = c
    return IV + bytes(ciphertext)

def cbc_decrypt(ciphertext_with_iv: bytes, round_keys) -> bytes:
    IV = ciphertext_with_iv[:16]
    body = ciphertext_with_iv[16:]
    blocks = [body[i:i+16] for i in range(0, len(body), 16)]
    previous = IV
    decrypted = bytearray()
    for c in blocks:
        d = aes_decrypt_block(c, round_keys)
        p = bytes(b1 ^ b2 for b1, b2 in zip(d, previous))
        decrypted.extend(p)
        previous = c
    return bytes(decrypted)

def demo_mode(mode: str, key_ascii: str, plaintext_ascii: str) -> None:
    assert mode in ("ECB", "CBC")
    key_bytes = key_ascii.encode('latin-1')
    plaintext_bytes = plaintext_ascii.encode('latin-1')

    print(f"{'=' * 25} AES / {mode} {'=' * 25}\n")

    print("Key:")
    print(f"In ASCII: {to_ascii_str(key_bytes)}")
    print(f"In HEX: {to_hex_str(key_bytes)}\n")

    print("Plain Text:")
    print(f"In ASCII: {to_ascii_str(plaintext_bytes)}")
    print(f"In HEX: {to_hex_str(plaintext_bytes)}")

    padded = pkcs7_pad(plaintext_bytes)
    print(f"In ASCII (After Padding): {to_ascii_str(padded)}")
    print(f"In HEX (After Padding): {to_hex_str(padded)}\n")

    key16 = normalize_key_to_16_bytes(key_bytes)
    with Timer() as t_ks:
        round_keys = key_expansion(key16)

    # for round_num, rk in enumerate(round_keys):
    #     print(f"Round {round_num:02d} Key: {rk.hex()}")

    with Timer() as t_enc:
        if mode == "ECB":
            ciphertext = ecb_encrypt(plaintext_bytes, round_keys)
        else:
            ciphertext = cbc_encrypt(plaintext_bytes, round_keys)

    print("Ciphered Text:")
    if mode == "CBC":
        print("(IV is the first 16 bytes, followed by the actual ciphertext)")
    print(f"In HEX: {to_hex_str(ciphertext)}")
    print(f"In ASCII: {to_ascii_str(ciphertext)}\n")

    with Timer() as t_dec:
        if mode == "ECB":
            decrypted_padded = ecb_decrypt(ciphertext, round_keys)
        else:
            decrypted_padded = cbc_decrypt(ciphertext, round_keys)

    print("Deciphered Text:")
    print("Before Unpadding:")
    print(f"In HEX: {to_hex_str(decrypted_padded)}")
    print(f"In ASCII: {to_ascii_str(decrypted_padded)}")

    recovered = pkcs7_unpad(decrypted_padded)
    print("After Unpadding:")
    print(f"In ASCII: {to_ascii_str(recovered)}")
    print(f"In HEX: {to_hex_str(recovered)}\n")

    assert recovered == plaintext_bytes, "Recovered text != original!"

    print("Execution Time Details:")
    print(f"Key Schedule Time: {t_ks.elapsed_ms} ms")
    print(f"Encryption Time: {t_enc.elapsed_ms} ms")
    print(f"Decryption Time: {t_dec.elapsed_ms} ms")


if __name__ == "__main__":
    demo_mode("CBC", key_ascii="BUET CSE20 Batch", plaintext_ascii="We need picnic")
    print()
    demo_mode("ECB", key_ascii="BUET CSE20 Batch", plaintext_ascii="We need picnic")
