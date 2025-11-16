import os
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes

@dataclass
class TranscriptLine:
    seq: int
    ts: int
    ct_b64: str
    sig_b64: str
    peer_fp_hex: str

def write_transcript_line(path: str, line: TranscriptLine):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{line.seq}|{line.ts}|{line.ct_b64}|{line.sig_b64}|{line.peer_fp_hex}\n")

def compute_transcript_hash(path: str) -> bytes:
    if not os.path.exists(path):
        data = b""
    else:
        with open(path, "rb") as f:
            data = f.read()
    d = hashes.Hash(hashes.SHA256()); d.update(data); return d.finalize()
