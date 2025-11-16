import base64, time, json, struct, socket
from cryptography.hazmat.primitives import hashes

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(b: bytes) -> str:
    d = hashes.Hash(hashes.SHA256()); d.update(b); return d.finalize().hex()

def sha256_bytes(b: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256()); d.update(b); return d.finalize()

# Length-prefixed JSON framing
def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_json(sock: socket.socket) -> dict:
    hdr = _recvn(sock, 4)
    if not hdr:
        raise ConnectionError("EOF")
    ln = struct.unpack("!I", hdr)[0]
    data = _recvn(sock, ln)
    return json.loads(data.decode("utf-8"))

def _recvn(sock: socket.socket, n: int) -> bytes:
    b = b""
    while len(b) < n:
        chunk = sock.recv(n - len(b))
        if not chunk:
            return b
        b += chunk
    return b
