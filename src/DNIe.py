#!/usr/bin/env python3
"""
dni_check_pin_mac.py
Detecta lector/DNIe vía PKCS#11 (OpenSC) en macOS y verifica si el PIN es correcto.

Uso: python3 dni_check_pin_mac.py
"""

import os
import sys
import getpass
from PyKCS11 import PyKCS11Lib, PyKCS11Error

# Rutas típicas de la librería PKCS#11 de OpenSC en macOS - se prueban en orden
POSSIBLE_PKCS11_PATHS = [
    "/opt/homebrew/lib/opensc-pkcs11.so",      # Homebrew en Apple Silicon / M1/M2
    "/usr/local/lib/opensc-pkcs11.so",        # Homebrew en Intel (antiguo)
    "/Library/OpenSC/lib/opensc-pkcs11.so",   # Instalador oficial OpenSC
    "/usr/lib/opensc-pkcs11.so",              # ruta posible
]

def find_pkcs11_lib():
    for p in POSSIBLE_PKCS11_PATHS:
        if os.path.exists(p):
            return p
    return None

def try_load_pkcs11(path):
    pk = PyKCS11Lib()
    pk.load(path)
    return pk

def main():
    print("=== Comprobador DNIe (macOS) — Verificar PIN via PKCS#11 (OpenSC) ===\n")

    libpath = find_pkcs11_lib()
    if not libpath:
        print("No he encontrado la librería PKCS#11 de OpenSC en rutas típicas.")
        print("Rutas probadas:")
        for p in POSSIBLE_PKCS11_PATHS:
            print("  -", p)
        print("\nInstala OpenSC (brew install opensc) o ajusta la ruta en el script.")
        sys.exit(1)

    print(f"Usando librería PKCS#11 encontrada en: {libpath}")

    try:
        pkcs11 = try_load_pkcs11(libpath)
    except Exception as e:
        print("Error al cargar la librería PKCS#11:", e)
        print("¿Coincide la arquitectura (x86_64 vs arm64)? Asegúrate de instalar la versión correcta de OpenSC.")
        sys.exit(1)

    # Obtener slots con token presente
    try:
        slots = pkcs11.getSlotList(tokenPresent=False)
    except Exception as e:
        print("Error al obtener slot list:", e)
        sys.exit(1)

    if not slots:
        print("No se han detectado tokens/DNIe en los slots. Posibles causas:")
        print("- Lector desconectado o no reconocido por macOS")
        print("- Tarjeta no insertada correctamente")
        print("- Driver/permiso de OpenSC")
        sys.exit(1)

    print(f"Tokens detectados: {len(slots)}. Usando el primer slot: {slots[0]}")
    slot = slots[0]

    # Muestra info del token (opcional, sin exponer datos sensibles)
    try:
        info = pkcs11.getTokenInfo(slot)
        print("Token label:", info.label.strip() if hasattr(info, "label") else "<desconocido>")
        # manufacturer, model, serial pueden estar disponibles también
    except Exception:
        pass

    # Pedimos el PIN de forma oculta
    pin = getpass.getpass("Introduce el PIN del DNIe (no se mostrará en pantalla): ")

    # Abrir sesión y probar login
    session = None
    try:
        session = pkcs11.openSession(slot)
    except Exception as e:
        print("Error al abrir sesión en el slot:", e)
        sys.exit(1)

    try:
        session.login(pin)
    except PyKCS11Error as e:
        # PyKCS11Error incluye normalmente el código PKCS#11.
        # CKR_PIN_INCORRECT suele corresponder a código 0x000000A0 (160 decimal), pero la
        # representación depende de la versión. Mostramos mensaje claro:
        errstr = str(e)
        if "CKR_PIN_INCORRECT" in errstr or "pin incorrect" in errstr.lower() or "160" in errstr:
            print("\nResultado: PIN INCORRECTO (login fallido).")
            print("Comprueba que el PIN es correcto. Ojo con bloqueo tras varios intentos.")
        else:
            # Otros errores: por ejemplo token bloqueado, requisitos de mecanismo, permisos...
            print("\nLogin fallido. Error devuelto por la librería PKCS#11:")
            print(" ", errstr)
        # Cerrar sesión si fue parcialmente abierta
        try:
            session.closeSession()
        except Exception:
            pass
        sys.exit(1)

    # Si llegamos aquí, login fue exitoso
    print("\nResultado: PIN correcto. Autenticación OK ✅")
    # opcional: listar certificados (solo para comprobar)
    try:
        from PyKCS11 import CKO_CERTIFICATE, CKA_LABEL, CKA_CLASS
        certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
        print(f"Certificados encontrados: {len(certs)}")
        for i, c in enumerate(certs, start=1):
            try:
                attrs = session.getAttributeValue(c, [CKA_LABEL])
                label = attrs[0].decode() if isinstance(attrs[0], bytes) else attrs[0]
            except Exception:
                label = "<sin label>"
            print(f"  {i}. {label}")
    except Exception:
        pass

    # Logout y cerrar
    try:
        session.logout()
    except Exception:
        pass
    try:
        session.closeSession()
    except Exception:
        pass

if __name__ == "__main__":
    main()
