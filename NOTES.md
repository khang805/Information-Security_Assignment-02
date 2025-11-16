# Manual evidence checklist
- Show encrypted payloads (no plaintext)
- BAD_CERT on invalid/self/expired cert
- SIG_FAIL on tamper (flip bit in ct)
- REPLAY on reused seqno
- Transcript + signed SessionReceipt


# Manual Testing & Wireshark Evidence

## Wireshark
- Capture on loopback port 8888: filter `tcp.port == 8888`.
- Show that register/login payloads are encrypted (no plaintext credentials).
- Show chat messages carry base64 ciphertext and signatures only.

## Invalid Certificate
- Regenerate client with CN `client.fake`: `python scripts/gen_cert.py client.fake client`
- Run client: server should reject with `BAD_CERT`.

## Tampering
- In client, mutate `ct_b64` before sending (flip a byte).
- Recipient should respond `SIG_FAIL`.

## Replay
- In client, send same `seqno` twice.
- Server should respond `REPLAY`.

## Non-Repudiation
- Check `logs/server_transcript_*.log` and `logs/client_transcript_*.log`.
- Each line: `seq|ts|ct|sig|peer-cert-fingerprint`.
- Verify receipt signature over transcript hash:
  - Client verifies server receipt.
  - Editing transcript invalidates verification (demonstrate failure).
