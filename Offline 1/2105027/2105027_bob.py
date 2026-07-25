import socket
import importlib

aes = importlib.import_module("2105027_aes_core")
dh = importlib.import_module("2105027_dh_core")
netutil = importlib.import_module("2105027_netutil")

HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 128 


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[BOB] listening on {HOST}:{PORT} ...")

        conn, addr = server.accept()
        with conn:
            print(f"[BOB] connection from {addr}")

            params = netutil.recv_json(conn)
            P, g, A = params["P"], params["g"], params["A"]

            Kb, B = dh.generate_private_public_pair(P, g, KEY_BITS)
            netutil.send_json(conn, {"B": B})

            shared_secret = dh.compute_shared_secret(A, Kb, P)
            print(f"[BOB] shared secret computed (s = {shared_secret})")

            aes_key = dh.derive_aes_key(shared_secret, KEY_BITS)
            round_keys = aes.key_expansion(aes_key)

            mode = netutil.recv_json(conn)["mode"]
            ciphertext = netutil.recv_msg(conn)

            if mode == "CBC":
                padded_plaintext = aes.cbc_decrypt(ciphertext, round_keys)
            else:
                padded_plaintext = aes.ecb_decrypt(ciphertext, round_keys)
            plaintext = aes.pkcs7_unpad(padded_plaintext)

            print(f"[BOB] received {len(ciphertext)}-byte {mode} ciphertext")
            print(f"[BOB] decrypted message: {aes.to_ascii_str(plaintext)!r}")


if __name__ == "__main__":
    main()
