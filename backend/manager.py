import string
import secrets as _secrets
import threading
import time
from typing import Optional
from storage.db import (
    insert_secret, list_secrets, get_secret_payload, update_secret,
    delete_secret, list_history, get_history_payload
)
from storage.crypto import encrypt_json, decrypt_json
from auth.master import Master
from auth.twofa import TwoFactorAuth

class SecretManager:
    def __init__(self):
        self.master = Master()
        self.two_fa = TwoFactorAuth()

    def initialized(self) -> bool:
        return self.master.has_salt()

    def create_master(self) -> None:
        self.master.create()

    def ask_master(self) -> None:
        self.master.ask()

    def verify_2fa(self, code: str) -> bool:
        """Проверка двухфакторной аутентификации"""
        return self.two_fa.verify_code(code)

    def is_2fa_enabled(self) -> bool:
        """Проверка, включена ли 2FA"""
        return self.two_fa.is_enabled()

    def setup_2fa(self, username: str = "SecretManager") -> tuple[str, str]:
        """Настройка двухфакторной аутентификации"""
        return self.two_fa.setup_new_2fa(username)

    def generate_2fa_qr_code(self, uri: str, save_path: str = "2fa_qr.png") -> str:
        """Генерация QR-кода для 2FA"""
        return self.two_fa.generate_qr_code(uri, save_path)

    def get_2fa_backup_codes(self) -> list[str]:
        """Получение резервных кодов для 2FA"""
        return self.two_fa.get_backup_codes()

    def disable_2fa(self):
        """Отключение двухфакторной аутентификации"""
        self.two_fa.disable_2fa()

    def add(self, name: str, data: dict, group: str = "default") -> int:
        if not self.master.key:
            raise RuntimeError("Master key not set")
        enc = encrypt_json(self.master.key, data)
        return insert_secret(name, enc, group)

    def list(self, query: Optional[str] = None):
        return list_secrets(query)

    def view(self, secret_id: int) -> dict:
        if not self.master.key:
            raise RuntimeError("Master key not set")
        blob = get_secret_payload(secret_id)
        if not blob:
            raise KeyError("Secret not found")
        return decrypt_json(self.master.key, blob)

    def update(self, secret_id: int, data: dict) -> None:
        if not self.master.key:
            raise RuntimeError("Master key not set")
        enc = encrypt_json(self.master.key, data)
        update_secret(secret_id, enc)

    def remove(self, secret_id: int) -> None:
        delete_secret(secret_id)

    def history_list(self, secret_id: int):
        return list_history(secret_id)

    def history_view(self, history_id: int) -> dict:
        if not self.master.key:
            raise RuntimeError("Master key not set")
        blob = get_history_payload(history_id)
        if not blob:
            raise KeyError("History not found")
        return decrypt_json(self.master.key, blob)

    def generate_password(self, length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return ''.join(_secrets.choice(alphabet) for _ in range(length))

    def copy_with_timeout(self, root, text: str, timeout: int = 15) -> None:
        try:
            root.clipboard_clear()
            root.clipboard_append(text)
        except Exception:
            return
        def _clear():
            time.sleep(timeout)
            try:
                root.clipboard_clear()
            except Exception:
                pass
        t = threading.Thread(target=_clear, daemon=True)
        t.start()

    def lock(self):
        """Блокировка менеджера"""
        self.master.lock()

    def unlock(self, password: str) -> bool:
        """Разблокировка менеджера"""
        return self.master.unlock(password)

    def is_locked(self) -> bool:
        """Проверка заблокирован ли менеджер"""
        return self.master.locked

    def validate_data_format(self, data_type: str, value: str) -> tuple[bool, str]:
        """Валидация форматов данных"""
        if not value:
            return True, ""
            
        if data_type == "email":
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if re.match(email_pattern, value):
                return True, "✓ Valid email"
            else:
                return False, "⚠ Invalid email format"
                
        elif data_type == "url":
            import re
            url_pattern = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/\S*)?$'
            if re.match(url_pattern, value):
                return True, "✓ Valid URL"
            else:
                return False, "⚠ Invalid URL format"
                
        elif data_type == "username":
            if len(value) >= 3:
                return True, "✓ Username"
            else:
                return False, "⚠ Too short (min 3 chars)"
                
        elif data_type == "phone":
            import re
            # Базовая валидация телефонного номера
            phone_pattern = r'^[\+]?[0-9\s\-\(\)]{10,}$'
            if re.match(phone_pattern, value.replace(" ", "")):
                return True, "✓ Phone number"
            else:
                return False, "⚠ Invalid phone format"
                
        return True, ""

    def check_password_strength(self, password: str) -> tuple[bool, str]:
        """Проверка сложности пароля (делегирует мастеру)"""
        return self.master.check_password_strength(password)

    def export_data(self, path: str, include_history: bool = False) -> bool:
        """Экспорт данных с дополнительными опциями"""
        try:
            from storage.export import export_json
            export_json(path, self.master.salt)
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False

    def import_data(self, path: str) -> bool:
        """Импорт данных"""
        try:
            from storage.export import import_json
            if not self.master.key:
                return False
            import_json(path, self.master.key)
            return True
        except Exception as e:
            print(f"Import error: {e}")
            return False

    def get_security_report(self) -> dict:
        """Генерация отчета о безопасности"""
        secrets = list_secrets()
        weak_passwords = 0
        reused_passwords = {}
        password_strengths = []
        
        for sid, name, _ in secrets:
            try:
                data = self.view(sid)
                password = data.get('password', '')
                
                # Проверка силы пароля
                is_strong, _ = self.check_password_strength(password)
                if not is_strong:
                    weak_passwords += 1
                
                # Проверка повторного использования
                if password in reused_passwords:
                    reused_passwords[password].append(name)
                else:
                    reused_passwords[password] = [name]
                    
                password_strengths.append({
                    'name': name,
                    'length': len(password),
                    'is_strong': is_strong
                })
                
            except Exception:
                continue
        
        # Фильтруем действительно повторно используемые пароли
        actually_reused = {pwd: names for pwd, names in reused_passwords.items() 
                          if len(names) > 1 and pwd}
        
        return {
            'total_secrets': len(secrets),
            'weak_passwords': weak_passwords,
            'reused_passwords_count': len(actually_reused),
            'reused_passwords_details': actually_reused,
            'password_strengths': password_strengths,
            '2fa_enabled': self.is_2fa_enabled(),
            'manager_locked': self.is_locked()
        }

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Смена мастер-пароля"""
        try:
            # Проверяем старый пароль
            test_key = self.master._derive(old_password, self.master.salt)
            if test_key != self.master.key:
                return False
            
            # Проверяем сложность нового пароля
            is_strong, message = self.check_password_strength(new_password)
            if not is_strong:
                # Можно добавить логирование или предупреждение
                pass
            
            # Генерируем новый ключ
            self.master.key = self.master._derive(new_password, self.master.salt)
            return True
            
        except Exception:
            return False

    def emergency_lock(self):
        """Аварийная блокировка - очистка всех чувствительных данных из памяти"""
        self.master.key = None
        self.master.locked = True
        # Дополнительные меры безопасности при необходимости
        import gc
        gc.collect()