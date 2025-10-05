import os
import base64
import sqlite3
import re
from typing import Optional
from tkinter import simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

DB_FILE = "secrets.db"
META_KEY = "salt"

class Master:
    def __init__(self):
        self.salt: Optional[bytes] = None
        self.key: Optional[bytes] = None
        self._load_salt()
        self.locked = False

    def _conn(self):
        return sqlite3.connect(DB_FILE)

    def _load_salt(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT v FROM meta WHERE k = ?", (META_KEY,))
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            self.salt = row[0]

    def has_salt(self) -> bool:
        return self.salt is not None

    def _derive(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    def check_password_strength(self, password: str) -> tuple[bool, str]:
        """Проверка сложности пароля"""
        if len(password) < 12:
            return False, "Пароль должен содержать минимум 12 символов"
        
        checks = {
            "строчные буквы": any(c.islower() for c in password),
            "заглавные буквы": any(c.isupper() for c in password),
            "цифры": any(c.isdigit() for c in password),
            "спецсимволы": any(c in "!@#$%^&*()-_=+[]{};:,.<>?/" for c in password)
        }
        
        missing = [name for name, check in checks.items() if not check]
        if missing:
            return False, f"Добавьте: {', '.join(missing)}"
        
        # Проверка на повторяющиеся последовательности
        if re.search(r'(.)\1{2,}', password):
            return False, "Слишком много повторяющихся символов"
        
        return True, "Надёжный пароль"

    def create(self) -> None:
        while True:
            pw1 = simpledialog.askstring("Создание мастер-пароля", 
                                       "Введите мастер-пароль (минимум 12 символов, включая буквы, цифры и спецсимволы):", 
                                       show="*")
            if not pw1:
                messagebox.showerror("Ошибка", "Мастер-пароль обязателен.")
                raise SystemExit
            
            is_strong, message = self.check_password_strength(pw1)
            if not is_strong:
                if not messagebox.askyesno("Слабый пароль", 
                                         f"{message}\n\nВы уверены, что хотите использовать этот пароль?"):
                    continue
                break
            else:
                break
        
        pw2 = simpledialog.askstring("Подтверждение", "Повторите мастер-пароль:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            raise SystemExit
        
        # Предложить создать резервную копию
        if messagebox.askyesno("Резервная копия", 
                             "Рекомендуется создать резервную копию мастер-пароля.\nСоздать сейчас?"):
            self._create_backup(pw1)
        
        self.salt = os.urandom(16)
        self.key = self._derive(pw1, self.salt)
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("REPLACE INTO meta (k, v) VALUES (?, ?)", (META_KEY, self.salt))
        conn.commit()
        conn.close()
        messagebox.showinfo("Успех", "Мастер-пароль создан.")

    def _create_backup(self, password: str):
        """Создание резервной копии мастер-пароля"""
        from datetime import datetime
        import json
        
        backup_data = {
            "created": datetime.now().isoformat(),
            "salt": base64.b64encode(self.salt).decode() if self.salt else None,
            "reminder": "Храните этот файл в безопасном месте!"
        }
        
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".backup",
            filetypes=[("Backup files", "*.backup")],
            title="Сохранить резервную копию"
        )
        if path:
            with open(path, 'w') as f:
                json.dump(backup_data, f, indent=2)
            messagebox.showinfo("Резервная копия", f"Резервная копия сохранена в: {path}")

    def restore_from_backup(self, backup_path: str, new_password: str) -> bool:
        """Восстановление из резервной копии"""
        try:
            import json
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)
            
            salt = base64.b64decode(backup_data['salt']) if backup_data.get('salt') else None
            if not salt:
                return False
            
            self.salt = salt
            self.key = self._derive(new_password, self.salt)
            
            conn = self._conn()
            cur = conn.cursor()
            cur.execute("REPLACE INTO meta (k, v) VALUES (?, ?)", (META_KEY, self.salt))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def ask(self) -> None:
        if not self.salt:
            messagebox.showerror("Ошибка", "Соль не найдена, требуется инициализация.")
            raise SystemExit
        pw = simpledialog.askstring("Мастер-пароль", "Введите мастер-пароль:", show="*")
        if not pw:
            raise SystemExit
        self.key = self._derive(pw, self.salt)

    def lock(self):
        """Блокировка мастер-ключа"""
        self.key = None
        self.locked = True

    def unlock(self, password: str) -> bool:
        """Разблокировка мастер-ключа"""
        try:
            self.key = self._derive(password, self.salt)
            self.locked = False
            return True
        except Exception:
            return False

    def force_set_from_password(self, password: str):
        if not self.salt:
            self.salt = os.urandom(16)
            conn = self._conn()
            cur = conn.cursor()
            cur.execute("REPLACE INTO meta (k, v) VALUES (?, ?)", (META_KEY, self.salt))
            conn.commit()
            conn.close()
        self.key = self._derive(password, self.salt)