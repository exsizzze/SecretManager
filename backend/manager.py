import secrets, string, time
import threading
from storage.db import insert_secret, list_secrets, get_secret_payload, insert_history
from storage.crypto import encrypt_json, decrypt_json
from auth.master import MasterPassword

class SecretManager:
    def __init__(self):
        self.master = MasterPassword()

    def is_initialized(self):
        return self.master.has_salt()

    def create_master_password(self):
        self.master.create()

    def ask_master_password(self):
        self.master.ask()

    def add_secret(self, name, data: dict, group="default"):
        enc = encrypt_json(self.master.key, data)
        insert_secret(name, enc, group)

    def list_secrets(self, query=None):
        return list_secrets(query)

    def view_secret(self, sid: int):
        payload = get_secret_payload(sid)
        return decrypt_json(self.master.key, payload)

    def generate_password(self, length=16):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return ''.join(secrets.choice(chars) for _ in range(length))

    def copy_with_timeout(self, text, tk_root, seconds=15):
        tk_root.clipboard_clear()
        tk_root.clipboard_append(text)
        def clear():
            time.sleep(seconds)
            tk_root.clipboard_clear()
        threading.Thread(target=clear, daemon=True).start()