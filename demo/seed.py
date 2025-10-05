from storage.db import init_db, insert_secret
from auth.master import Master
from storage.crypto import encrypt_json

def seed():
    init_db()
    m = Master()
    if not m.has_salt():
        m.force_set_from_password("demo")
    examples = [
        ("Demo Email", {"username":"demo@example.com", "password":"email-demo-123"}),
        ("Demo DB", {"username":"dbadmin", "password":"dbpass!"}),
        ("API Key", {"token":"AKIAxxxxxxxxxxxxxxxx"})
    ]
    for name, data in examples:
        enc = encrypt_json(m.key, data)
        insert_secret(name, enc, group_name="demo")
    print("Seeded demo data (master password = 'demo' if not set).")

if __name__ == "__main__":
    seed()