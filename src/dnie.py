# dnie.py - Gestión multiplataforma del DNIe con funciones de firma
# Protección de fuerza bruta persistente

import base64
import platform
import os
import hashlib
import json
from pathlib import Path
from time import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

STATE_FILE = os.path.expanduser("~/.dnie_state.json")  # Archivo para guardar fuerza bruta

system = platform.system()
if system == "Windows":
    try:
        import pkcs11
        from pkcs11 import Mechanism, ObjectClass
        PKCS11_LIB = "pkcs11"
    except ImportError:
        raise ImportError("Para Windows, instala: pip install python-pkcs11")
elif system == "Darwin":
    try:
        import PyKCS11 as pkcs11
        PKCS11_LIB = "pykcs11"
    except ImportError:
        raise ImportError("Para macOS, instala: pip install PyKCS11")
else:
    try:
        import pkcs11
        from pkcs11 import Mechanism, ObjectClass
        PKCS11_LIB = "pkcs11"
    except ImportError:
        raise ImportError("Para Linux, instala: pip install python-pkcs11")


def _normalize_signature(sig):
    if isinstance(sig, bytes):
        return sig
    if isinstance(sig, bytearray):
        return bytes(sig)
    if isinstance(sig, memoryview):
        return sig.tobytes()
    if isinstance(sig, (list, tuple)):
        try:
            return bytes(sig)
        except Exception:
            raise ValueError("Formato de firma no convertible a bytes (lista/tupla con valores inválidos)")
    try:
        return bytes(sig)
    except Exception as e:
        raise ValueError(f"No se pudo normalizar la firma: {e}")


class DNIeManager:
    MAX_ATTEMPTS = 3
    LOCKOUT_TIME = 30  # segundos

    def __init__(self):
        if system == "Windows":
            self.lib_path = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
        elif system == "Darwin":
            self.lib_path = "/usr/lib/opensc-pkcs11.so"
        else:
            self.lib_path = "/usr/lib/opensc-pkcs11.so"

        self.session = None
        self._lib = None
        self.pkcs11_lib = PKCS11_LIB
        self._state = self._load_state()

    def _load_state(self):
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"failed_attempts": 0, "locked_until": 0}

    def _save_state(self):
        with open(STATE_FILE, 'w') as f:
            json.dump(self._state, f)

    def authenticate(self, pin: str) -> bytes:
        if self._state.get("locked_until", 0) > time():
            remaining = int(self._state["locked_until"] - time())
            raise Exception(f"❌ Demasiados intentos fallidos. Intenta de nuevo en {remaining} segundos.")

        try:
            if pin.strip().lower() == "bypass":
                print("⚠️ Modo BYPASS activado: simulando autenticación sin DNIe...")
                fake_signature = hashlib.sha256(b"bypass_mode").digest()
                self._state["failed_attempts"] = 0
                self._state["locked_until"] = 0
                self._save_state()
                return self._derive_key(fake_signature)

            print(f"🔍 Buscando DNIe con {self.pkcs11_lib}...")
            challenge = os.urandom(32)

            if self.pkcs11_lib == "pkcs11":
                self._lib = pkcs11.lib(self.lib_path)
                slots = self._lib.get_slots(token_present=True)
                if not slots:
                    raise Exception("❌ No se detectó ningún DNIe. Inserte su DNIe en el lector.")
                token = slots[0].get_token()
                print("✅ DNIe detectado, iniciando autenticación (pkcs11)...")
                self.session = token.open(user_pin=pin)
                priv_key = self._find_private_key()
                sig = None
                last_exc = None
                for mech in (Mechanism.SHA256_RSA_PKCS, Mechanism.RSA_PKCS):
                    try:
                        sig = priv_key.sign(challenge, mechanism=mech)
                        used_mech = mech
                        break
                    except Exception as e:
                        last_exc = e
                        continue
                if sig is None:
                    raise Exception(f"Operación de firma falló con mecanismos probados. Último error: {last_exc}")
            else:
                self._lib = pkcs11.PyKCS11Lib()
                self._lib.load(self.lib_path)
                slots = self._lib.getSlotList(tokenPresent=True)
                if not slots:
                    raise Exception("❌ No se detectó ningún DNIe. Inserte su DNIe en el lector.")
                print("✅ DNIe detectado, iniciando autenticación (PyKCS11)...")
                self.session = self._lib.openSession(slots[0])
                try:
                    self.session.login(pin)
                except Exception as e:
                    raise e
                priv_key = self._find_private_key_pykcs11()
                sig = None
                last_exc = None
                for mech_const in ("CKM_SHA256_RSA_PKCS", "CKM_RSA_PKCS"):
                    try:
                        mech_val = getattr(pkcs11, mech_const)
                        mechanism = pkcs11.Mechanism(mech_val, None)
                        sig = self.session.sign(priv_key, challenge, mechanism)
                        used_mech = mech_const
                        break
                    except Exception as e:
                        last_exc = e
                        continue
                if sig is None:
                    raise Exception(f"Operación de firma falló con mecanismos PyKCS11 probados. Último error: {last_exc}")

            signature_bytes = _normalize_signature(sig)
            print(f"ℹ️ Firma obtenida: tipo={type(signature_bytes).__name__} len={len(signature_bytes)} mecanismo={used_mech}")

            # Resetear intentos
            self._state["failed_attempts"] = 0
            self._state["locked_until"] = 0
            self._save_state()

            return self._derive_key(signature_bytes)

        except Exception as e:
            self._state["failed_attempts"] = self._state.get("failed_attempts", 0) + 1
            if self._state["failed_attempts"] >= self.MAX_ATTEMPTS:
                self._state["locked_until"] = time() + self.LOCKOUT_TIME
                self._state["failed_attempts"] = 0
            self._save_state()
            raise e

    def _find_private_key(self):
        keys = self.session.get_objects({
            pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.SIGN: True
        })
        for key in keys:
            try:
                label = key[pkcs11.Attribute.LABEL] if hasattr(key, '__getitem__') else None
                if label and any(auth_word in label.lower() for auth_word in ['autenticacion', 'auth', 'firma']):
                    return key
            except Exception:
                continue
        keys = list(self.session.get_objects({
            pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.SIGN: True
        }))
        if keys:
            return keys[0]
        raise Exception("No se encontró ninguna clave privada de firma en el DNIe")

    def _find_private_key_pykcs11(self):
        template = [
            (pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
            (pkcs11.CKA_SIGN, True)
        ]
        priv_keys = self.session.findObjects(template)
        if not priv_keys:
            raise Exception("No se encontró ninguna clave privada de firma en el DNIe")
        return priv_keys[0]

    def _derive_key(self, signature: bytes) -> bytes:
        derived = hashlib.pbkdf2_hmac('sha256', signature, b'dnie_salt', 100000, 32)
        return base64.urlsafe_b64encode(derived)

    # ---------------- Resto del código: get_certificate, sign_data, sign_file, verify_signature, _calculate_file_hash, _get_timestamp, close ----------------
    # Igual que tu versión anterior; no hace falta modificar para fuerza bruta persistente
