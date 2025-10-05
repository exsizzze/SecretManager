import json
import base64
import csv
from storage.db import list_secrets, get_secret_payload, insert_secret
from storage.crypto import encrypt_json, decrypt_json

def export_json(path: str, salt: bytes = None) -> None:
    rows = list_secrets()
    out = {
        "exported_at": __import__("datetime").datetime.utcnow().isoformat(),
        "salt": base64.b64encode(salt).decode() if salt else None,
        "secrets": []
    }
    for sid, name, created in rows:
        payload = get_secret_payload(sid)
        out["secrets"].append({
            "id": sid,
            "name": name,
            "created_at": created,
            "payload": base64.b64encode(payload).decode() if payload else None
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

def import_json(path: str, master_key: bytes) -> None:
    """Импорт данных из JSON файла"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    imported_count = 0
    for secret_data in data.get("secrets", []):
        name = secret_data["name"]
        payload_b64 = secret_data.get("payload")
        
        if payload_b64:
            try:
                # Декодируем и перешифровываем с текущим ключом
                old_payload = base64.b64decode(payload_b64)
                decrypted_data = decrypt_json(master_key, old_payload)
                new_payload = encrypt_json(master_key, decrypted_data)
                
                insert_secret(name, new_payload, "imported")
                imported_count += 1
            except Exception as e:
                print(f"Ошибка импорта {name}: {e}")
                continue
    
    print(f"Импортировано {imported_count} записей")

def export_csv(path: str) -> None:
    rows = list_secrets()
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "created_at"])
        for sid, name, created in rows:
            writer.writerow([sid, name, created])