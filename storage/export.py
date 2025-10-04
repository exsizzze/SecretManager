import json, csv, base64
from storage.db import list_secrets, get_secret_payload

def export_json(path, secrets, salt):
    out = {
        "salt": base64.b64encode(salt).decode(),
        "secrets": []
    }
    for sid, name, created in secrets:
        payload = get_secret_payload(sid)
        out["secrets"].append({
            "id": sid, "name": name, "created_at": created,
            "payload": base64.b64encode(payload).decode()
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

def export_csv(path, secrets):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id","name","created_at"])
        for sid, name, created in secrets:
            writer.writerow([sid, name, created])