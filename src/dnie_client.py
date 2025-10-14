import platform
import pkcs11
from pkcs11 import Mechanism, ObjectClass
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class DNIeClient:
    def __init__(self, lib_path: str = None):
        if lib_path:
            self.lib_path = lib_path
        else:
            system = platform.system()
            if system == "Windows":
                self.lib_path = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
            elif system == "Darwin":
                self.lib_path = "/Library/OpenSC/lib/opensc-pkcs11.so"
            else:
                self.lib_path = "/usr/lib/opensc-pkcs11.so"
        self.session = None
        self._lib = None

    def connect(self, pin: str) -> bool:
        """Conectar con DNIe y abrir sesión"""
        self._lib = pkcs11.lib(self.lib_path)
        slots = self._lib.get_slots(token_present=True)
        if not slots:
            raise Exception("No se ha detectado ningún DNIe. Inserta la tarjeta.")
        token = slots[0].get_token()
        self.session = token.open(user_pin=pin)
        return True

    def get_certificate(self) -> bytes:
        """Extraer certificado X.509 del DNIe"""
        if not self.session:
            raise Exception("No conectado al DNIe")
        certs = self.session.get_objects({pkcs11.Attribute.CLASS: ObjectClass.CERTIFICATE})
        cert = next(certs, None)
        return bytes(cert[pkcs11.Attribute.VALUE]) if cert else None

    def sign_data(self, data: bytes, mechanism=Mechanism.SHA256_RSA_PKCS) -> bytes:
        """Firmar datos con la clave privada del DNIe"""
        if not self.session:
            raise Exception("No conectado al DNIe")
        keys = self.session.get_objects({
            pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.SIGN: True
        })
        priv_key = next(keys, None)
        if not priv_key:
            raise Exception("No se encontró clave privada de firma")
        return bytes(priv_key.sign(data, mechanism=mechanism))

    def verify_signature(self, data: bytes, signature: bytes, certificate: bytes) -> bool:
        """Verificar firma usando certificado"""
        try:
            cert_obj = x509.load_der_x509_certificate(certificate)
            pub_key = cert_obj.public_key()
            pub_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

    def close(self):
        """Cerrar sesión del DNIe"""
        if self.session:
            self.session.close()
            self.session = None