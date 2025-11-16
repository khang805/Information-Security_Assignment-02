#!/usr/bin/env python3
import os, socket, threading, json, secrets, time
from dotenv import load_dotenv
from app.crypto.aes import aes_decrypt_ecb, aes_encrypt_ecb
from app.crypto.dh import DH_G, DH_P, dh_generate_private, dh_public, dh_shared, k_from_shared
from app.crypto.pki import validate_cert, cert_fingerprint_sha256
from app.crypto.sign import rsa_verify_pkcs1v15, rsa_sign_pkcs1v15
from app.common.utils import send_json, recv_json, b64d, b64e, now_ms, sha256_bytes
from app.common.protocol import *
from app.storage.db import DB, DBConfig
from app.storage.transcript import write_transcript_line, compute_transcript_hash

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8888"))

CA_CERT_PATH = os.getenv("CA_CERT")
SERVER_CERT_PATH = os.getenv("SERVER_CERT")
SERVER_KEY_PATH = os.getenv("SERVER_KEY")

DB_CFG = DBConfig(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "3306")),
    name=os.getenv("DB_NAME", "securechat"),
    user=os.getenv("DB_USER", "securechat_user"),
    password=os.getenv("DB_PASS", "replace_me"),
)

LOG_DIR = os.getenv("LOG_DIR", "logs")

def is_fresh(ts_ms: int, skew_ms: int = 120_000) -> bool:
    return abs(now_ms() - ts_ms) <= skew_ms

class ReplayWindow:
    def __init__(self):
        self.last = -1
    def accept(self, seq: int) -> bool:
        if seq <= self.last: return False
        self.last = seq; return True

def handle(conn: socket.socket, addr):
    db = DB(DB_CFG)
    try:
        # 1) Send server hello
        server_nonce = secrets.token_bytes(16)
        srv_hello = ServerHello(server_cert=open(SERVER_CERT_PATH, "r").read(), nonce=b64e(server_nonce))
        send_json(conn, srv_hello.model_dump())

        # 2) Receive client hello and validate
        hello = Hello(**recv_json(conn))
        valid, code = validate_cert(hello.client_cert.encode("utf-8"), open(CA_CERT_PATH, "rb").read(), expected_cn="client.local")
        if not valid:
            send_json(conn, {"type":"error", "code":"BAD_CERT"})
            return

        # 3) Ephemeral DH for encrypted auth payload
        dhc = DHClient(**recv_json(conn))
        b = dh_generate_private()
        B = dh_public(dhc.g, dhc.p, b)
        send_json(conn, DHServer(B=B).model_dump())
        Ks = dh_shared(dhc.A, dhc.p, b)
        K = k_from_shared(Ks)

        # 4) Receive encrypted register/login
        auth_msg = recv_json(conn)
        if auth_msg["type"] not in ("register", "login"):
            send_json(conn, {"type":"error", "code":"BAD_AUTH_TYPE"})
            return

        iv_b64 = auth_msg.get("iv")  # optional for ECB; included to match model
        ct = b64d(auth_msg["ct"])
        try:
            payload = json.loads(aes_decrypt_ecb(K, ct).decode("utf-8"))
        except Exception:
            send_json(conn, {"type":"error", "code":"AUTH_DECRYPT_FAIL"})
            return

        if auth_msg["type"] == "register":
            email = payload["email"]; username = payload["username"]; password = payload["password"]
            salt = secrets.token_bytes(16)
            from app.common.utils import sha256_hex
            pwd_hash_hex = sha256_hex(salt + password.encode("utf-8"))
            ok = db.register_user(email, username, salt, pwd_hash_hex)
            send_json(conn, AuthResult(ok=ok, kind="register").model_dump())
            if not ok: return
        else:
            username = payload.get("username"); email = payload.get("email"); password = payload["password"]
            row = db.get_user(username=username, email=email)
            if not row:
                send_json(conn, AuthResult(ok=False, kind="login").model_dump())
                return
            _, salt, stored = row
            from app.common.utils import sha256_hex
            ok = (sha256_hex(salt + password.encode("utf-8")) == stored)
            send_json(conn, AuthResult(ok=ok, kind="login").model_dump())
            if not ok: return

        # 5) Post-auth DH for session key
        dh2c = DHClient(**recv_json(conn))
        b2 = dh_generate_private()
        B2 = dh_public(dh2c.g, dh2c.p, b2)
        send_json(conn, DHServer(B=B2).model_dump())
        Ks2 = dh_shared(dh2c.A, dh2c.p, b2)
        K2 = k_from_shared(Ks2)

        # 6) Chat loop
        send_json(conn, ChatReady().model_dump())
        client_cert_pem = hello.client_cert.encode("utf-8")
        peer_fp = cert_fingerprint_sha256(client_cert_pem)
        transcript_path = os.path.join(LOG_DIR, f"server_transcript_{int(time.time())}.log")
        replay = ReplayWindow()
        first_seq = None; last_seq = None

        while True:
            m = recv_json(conn)
            if m.get("type") == "close": break
            msg = Msg(**m)
            if not replay.accept(msg.seqno):
                send_json(conn, {"type":"error", "code":"REPLAY"}); continue
            if not is_fresh(msg.ts):
                send_json(conn, {"type":"error", "code":"STALE"}); continue
            # Verify signature
            data = f"{msg.seqno}|{msg.ts}|{msg.ct}".encode("utf-8")
            from app.common.utils import sha256_bytes
            h = sha256_bytes(data)
            if not rsa_verify_pkcs1v15("certs/client.cert.pem", h, b64d(msg.sig)):
                send_json(conn, {"type":"error", "code":"SIG_FAIL"}); continue
            # Decrypt
            payload = json.loads(aes_decrypt_ecb(K2, b64d(msg.ct)).decode("utf-8"))
            # Respond (echo)
            response_text = f"SERVER_ECHO: {payload['text']}"
            ct2 = aes_encrypt_ecb(K2, json.dumps({"text": response_text}).encode("utf-8"))
            seq2 = msg.seqno; ts2 = now_ms()
            ct2_b64 = b64e(ct2)
            h2 = sha256_bytes(f"{seq2}|{ts2}|{ct2_b64}".encode("utf-8"))
            sig2_b64 = b64e(rsa_sign_pkcs1v15(SERVER_KEY_PATH, h2))
            send_json(conn, Msg(seqno=seq2, ts=ts2, ct=ct2_b64, sig=sig2_b64).model_dump())
            # Transcript
            write_transcript_line(transcript_path,
                line=type("TL", (), {"seq": msg.seqno, "ts": msg.ts, "ct_b64": msg.ct, "sig_b64": msg.sig, "peer_fp_hex": peer_fp})()
            )
            first_seq = msg.seqno if first_seq is None else first_seq
            last_seq = msg.seqno

        # 7) Receipt
        th = compute_transcript_hash(transcript_path)
        sig = b64e(rsa_sign_pkcs1v15(SERVER_KEY_PATH, th))
        send_json(conn, Receipt(peer="server", first_seq=first_seq or 0, last_seq=last_seq or 0,
                                transcript_sha256=th.hex(), sig=sig).model_dump())

    except Exception:
        try: send_json(conn, {"type":"error", "code":"SERVER_EXCEPTION"})
        except Exception: pass
    finally:
        conn.close()

def main():
    if not all([CA_CERT_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH]):
        print("Set CA_CERT, SERVER_CERT, SERVER_KEY in .env")
        return
    os.makedirs(os.getenv("LOG_DIR", "logs"), exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SERVER_HOST, SERVER_PORT))
    srv.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
