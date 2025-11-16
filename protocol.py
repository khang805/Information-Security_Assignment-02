from pydantic import BaseModel
from typing import Optional

# Message models

class Hello(BaseModel):
    type: str = "hello"
    client_cert: str  # PEM text
    nonce: str        # base64

class ServerHello(BaseModel):
    type: str = "server hello"
    server_cert: str
    nonce: str

class DHClient(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int

class DHServer(BaseModel):
    type: str = "dh_server"
    B: int

class Register(BaseModel):
    type: str = "register"
    iv: str
    ct: str

class Login(BaseModel):
    type: str = "login"
    iv: str
    ct: str

class AuthResult(BaseModel):
    type: str = "auth_result"
    ok: bool
    kind: str  # register|login

class Msg(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct: str
    sig: str
    iv: Optional[str] = None  # ECB has no IV; kept optional for flexibility

class ChatReady(BaseModel):
    type: str = "chat_ready"

class Close(BaseModel):
    type: str = "close"

class Receipt(BaseModel):
    type: str = "receipt"
    peer: str          # client|server
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str
