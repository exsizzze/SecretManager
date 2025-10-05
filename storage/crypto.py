import json
from cryptography.fernet import Fernet

def encrypt_json(key: bytes, payload: dict) -> bytes:
    f = Fernet(key)
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return f.encrypt(raw)

def decrypt_json(key: bytes, token: bytes) -> dict:
    f = Fernet(key)
    raw = f.decrypt(token)
    return json.loads(raw.decode("utf-8"))