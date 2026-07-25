import importlib
import socket

aes = importlib.import_module("2105027_aes_core")
dh = importlib.import_module("2105027_dh_core")
netutil = importlib.import_module("2105027_netutil")

HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 128     
MODE = "CBC"      
MESSAGE = "We need picnic"


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[ALICE] connected to BOB at {HOST}:{PORT}")

        P, g = dh.generate_public_parameters(KEY_BITS)
        Ka, A = dh.generate_private_public_pair(P, g, KEY_BITS)
        netutil.send_json(sock, {"P": P, "g": g, "A": A})

        B = netutil.recv_json(sock)["B"]
        shared_secret = dh.compute_shared_secret(B, Ka, P)
        print(f"[ALICE] shared secret computed (s = {shared_secret})")

        aes_key = dh.derive_aes_key(shared_secret, KEY_BITS)
        round_keys = aes.key_expansion(aes_key)

        plaintext = MESSAGE.encode("latin-1")
        if MODE == "CBC":
            ciphertext = aes.cbc_encrypt(plaintext, round_keys)
        else:
            ciphertext = aes.ecb_encrypt(plaintext, round_keys)

        netutil.send_json(sock, {"mode": MODE})
        netutil.send_msg(sock, ciphertext)
        print(f"[ALICE] sent {len(ciphertext)}-byte {MODE} ciphertext: {MESSAGE!r}")


if __name__ == "__main__":
    main()
