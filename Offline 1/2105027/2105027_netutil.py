import json
import socket
import struct


def send_msg(conn: socket.socket, data: bytes) -> None:
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before expected data arrived")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(conn: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(conn, 4))
    return recv_exact(conn, length)


def send_json(conn: socket.socket, obj) -> None:
    send_msg(conn, json.dumps(obj).encode("utf-8"))


def recv_json(conn: socket.socket):
    return json.loads(recv_msg(conn).decode("utf-8"))


def load_numeric_module(path: str, module_name: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
