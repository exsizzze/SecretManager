import pyotp
import qrcode
import base64
import os
from typing import Optional

class TwoFactorAuth:
    def __init__(self):
        self.secret_file = "2fa_secret.txt"
        self.secret: Optional[str] = None
        self._load_secret()

    def _load_secret(self):
        """Загрузка секрета 2FA из файла"""
        if os.path.exists(self.secret_file):
            with open(self.secret_file, 'r') as f:
                self.secret = f.read().strip()

    def is_enabled(self) -> bool:
        """Проверка, включена ли 2FA"""
        return self.secret is not None

    def setup_new_2fa(self, username: str = "SecretManager") -> tuple[str, str]:
        """Настройка новой 2FA"""
        self.secret = pyotp.random_base32()
        
        # Сохранение секрета
        with open(self.secret_file, 'w') as f:
            f.write(self.secret)
        
        # Генерация URI для QR-кода
        totp = pyotp.TOTP(self.secret)
        uri = totp.provisioning_uri(
            name=username,
            issuer_name="SecretManager"
        )
        
        return self.secret, uri

    def generate_qr_code(self, uri: str, save_path: str = "2fa_qr.png"):
        """Генерация QR-кода"""
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(save_path)
            return save_path
        except Exception as e:
            print(f"QR code generation error: {e}")
            return None

    def verify_code(self, code: str) -> bool:
        """Проверка 2FA кода"""
        if not self.secret:
            return False
        
        # Очистка кода от пробелов
        code = code.replace(" ", "").strip()
        
        totp = pyotp.TOTP(self.secret)
        return totp.verify(code)

    def disable_2fa(self):
        """Отключение 2FA"""
        if os.path.exists(self.secret_file):
            os.remove(self.secret_file)
        self.secret = None

    def get_backup_codes(self) -> list[str]:
        """Генерация резервных кодов"""
        return [pyotp.random_base32() for _ in range(6)]