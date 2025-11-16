#!/usr/bin/env python3
import os, socket, json, time
from dotenv import load_dotenv
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.dh import DH_P, DH_G, dh_generate_private, dh_public, dh_shared, k_from_shared
from app.crypto.pki import validate_cert, cert_fingerprint_sha256
from app.crypto.sign import rsa_sign_pkcs1v15, rsa_verify_pkcs1v15
from app.common.utils import send_json, recv_json, b64e, b64d, now_ms, sha256_bytes
from app.common.protocol import *
from app.storage.transcript import write_transcript_line, compute_transcript_hash

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8888"))

CA_CERT_PATH = os.getenv("CA_CERT")
CLIENT_CERT_PATH = os.getenv("CLIENT_CERT")
CLIENT_KEY_PATH = os.getenv("CLIENT_KEY")

LOG_DIR = os.getenv("LOG_DIR", "logs")

def is_fresh(ts_ms: int, skew_ms: int = 120_000) -> bool:
    return abs(now_ms() - ts_ms) <= skew_ms

class ReplayWindow:
    def __init__(self): self.last = -1
    def accept(self, seq: int) -> bool:
        if seq <= self.last: return False
        self.last = seq; return True

def main():
    if not all([CA_CERT_PATH, CLIENT_CERT_PATH, CLIENT_KEY_PATH]):
        print("Set CA_CERT, CLIENT_CERT, CLIENT_KEY in .env")
        return

    os.makedirs(LOG_DIR, exist_ok=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))

    # 1) Receive server hello, validate server cert
    srv_hello = ServerHello(**recv_json(s))
    valid, code = validate_cert(srv_hello.server_cert.encode("utf-8"), open(CA_CERT_PATH, "rb").read(), expected_cn="server.local")
    if not valid:
        print("BAD_CERT:", code); return

    # 2) Send client hello
    client_nonce = os.urandom(16)
    send_json(s, Hello(client_cert=open(CLIENT_CERT_PATH, "r").read(), nonce=b64e(client_nonce)).model_dump())

    # 3) Ephemeral DH for encrypted auth
    a = dh_generate_private()
    A = dh_public(DH_G, DH_P, a)
    send_json(s, DHClient(g=DH_G, p=DH_P, A=A).model_dump())
    dhs = DHServer(**recv_json(s))
    Ks = dh_shared(dhs.B, DH_P, a)
    K = k_from_shared(Ks)

    # 4) Register or login
    choice = input("register or login? ").strip().lower()
    if choice == "register":
        email = input("email: ").strip()
        username = input("username: ").strip()
        password = input("password: ").strip()
        ct = aes_encrypt_ecb(K, json.dumps({"email": email, "username": username, "password": password}).encode("utf-8"))
        send_json(s, Register(ct=b64e(ct), iv="").model_dump())
    else:
        username = input("username (blank to use email): ").strip()
        email = input("email (optional): ").strip()
        password = input("password: ").strip()
        ct = aes_encrypt_ecb(K, json.dumps({"username": username or None, "email": email or None, "password": password}).encode("utf-8"))
        send_json(s, Login(ct=b64e(ct), iv="").model_dump())

    auth = AuthResult(**recv_json(s))
    if not auth.ok:
        print("Auth failed."); return
    print(f"Auth OK ({auth.kind})")

    # 5) Post-auth DH
    a2 = dh_generate_private()
    A2 = dh_public(DH_G, DH_P, a2)
    send_json(s, DHClient(g=DH_G, p=DH_P, A=A2).model_dump())
    dh2s = DHServer(**recv_json(s))
    Ks2 = dh_shared(dh2s.B, DH_P, a2)
    K2 = k_from_shared(Ks2)

    # 6) Chat
    ready = ChatReady(**recv_json(s))
    transcript_path = os.path.join(LOG_DIR, f"client_transcript_{int(time.time())}.log")

    seq = 0
    recv_replay = ReplayWindow()

    print("Type messages, 'exit' to quit.")
    while True:
        text = input("> ").strip()
        if text.lower() == "exit":
            send_json(s, Close().model_dump())
            break

        seq += 1
        ts = now_ms()
        ct = aes_encrypt_ecb(K2, json.dumps({"text": text}).encode("utf-8"))
        ct_b64 = b64e(ct)
        h = sha256_bytes(f"{seq}|{ts}|{ct_b64}".encode("utf-8"))
        sig_b64 = b64e(rsa_sign_pkcs1v15(CLIENT_KEY_PATH, h))
        send_json(s, Msg(seqno=seq, ts=ts, ct=ct_b64, sig=sig_b64).model_dump())

        # Receive echo
        reply_raw = recv_json(s)
        if reply_raw.get("type") != "msg":
            print("Error:", reply_raw); continue
        reply = Msg(**reply_raw)
        if not recv_replay.accept(reply.seqno):
            print("REPLAY detected."); continue
        if not is_fresh(reply.ts):
            print("STALE message."); continue
        h2 = sha256_bytes(f"{reply.seqno}|{reply.ts}|{reply.ct}".encode("utf-8"))
        if not rsa_verify_pkcs1v15(os.getenv("SERVER_CERT", "certs/server.cert.pem"), h2, b64d(reply.sig)):
            print("SIG_FAIL"); continue
        payload = json.loads(aes_decrypt_ecb(K2, b64d(reply.ct)).decode("utf-8"))
        print("<", payload["text"])

        # Log server message line
        server_cert_pem = open(os.getenv("SERVER_CERT", "certs/server.cert.pem"), "rb").read()
        peer_fp = cert_fingerprint_sha256(server_cert_pem)
        write_transcript_line(transcript_path,
            line=type("TL", (), {"seq": reply.seqno, "ts": reply.ts, "ct_b64": reply.ct, "sig_b64": reply.sig, "peer_fp_hex": peer_fp})()
        )

    # 7) Verify receipt from server
    receipt = Receipt(**recv_json(s))
    th = compute_transcript_hash(transcript_path)
    ok = rsa_verify_pkcs1v15(os.getenv("SERVER_CERT", "certs/server.cert.pem"), th, b64d(receipt.sig))
    print("Receipt verify:", ok)
    s.close()

if __name__ == "__main__":
    main()
