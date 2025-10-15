# login_qr_scan.py
"""
Módulo reutilizable para mostrar el QR TOTP y verificar códigos desde otra ventana Tk.
Funciones públicas principales:
- mostrar_qr(parent=None): muestra el QR en un Toplevel (no verifica) — útil para reconfigurar.
- verificar_codigo(parent=None): pide el código por dialog y devuelve True/False.
- mostrar_qr_y_verificar(parent=None): si no existe secreto muestra QR para registrar y luego
  pide/verifica el código; si ya existe, solo pide/verifica el código.
El fichero de secreto se guarda en SECRET_FILE para persistencia.
"""

import os
import pyotp
import qrcode
import tkinter as tk
from tkinter import simpledialog, messagebox
from PIL import Image, ImageTk

# Ruta del archivo donde se guarda la clave secreta (persistencia)
SECRET_FILE = os.path.join(os.path.expanduser("~"), ".vault_totp_secret")

# --- Utilidades internas ---
def _load_or_generate_secret():
    """Carga el secreto desde SECRET_FILE o genera uno nuevo y lo escribe.
    Devuelve (secret, newly_created_bool).
    """
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, "r", encoding="utf-8") as f:
                secret = f.read().strip()
            if secret:
                return secret, False
        except Exception:
            pass  # si falla la lectura, generamos nuevo
    # generar nuevo secreto y persistirlo
    secret = pyotp.random_base32()
    try:
        with open(SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(secret)
    except Exception as e:
        # Si no se puede escribir, aún devolvemos el secreto generado (no persistido)
        print("Warning: no se pudo guardar SECRET_FILE:", e)
    return secret, True

def _get_totp_from_secret(secret):
    return pyotp.TOTP(secret)

# --- Funciones públicas ---

def mostrar_qr(parent=None, account_name="usuario@ejemplo.com", issuer_name="MiApp"):
    """
    Muestra el QR en una ventana Toplevel. No verifica el código.
    parent: ventana padre (tk/Tk/CTk). Si es None, se creará un root temporal (solo si se ejecuta standalone).
    """
    # Cargar o generar secreto (no sobrescribe si ya existe)
    secret, newly_created = _load_or_generate_secret()
    totp = _get_totp_from_secret(secret)

    uri = totp.provisioning_uri(name=account_name, issuer_name=issuer_name)
    qr_img = qrcode.make(uri)

    # Si no se ha pasado parent (ejecución standalone), crear uno temporal.
    created_root = False
    if parent is None:
        parent = tk.Tk()
        parent.withdraw()
        created_root = True

    win = tk.Toplevel(parent)
    win.title("Escanea el QR con Google Authenticator")
    win.resizable(False, False)

    # Convertir imagen y mostrar
    qr_img_resized = qr_img.resize((260, 260))
    qr_photo = ImageTk.PhotoImage(qr_img_resized)

    lbl = tk.Label(win, image=qr_photo)
    lbl.image = qr_photo  # evitar garbage collection
    lbl.pack(padx=12, pady=(12, 6))

    info = tk.Label(win, text="Escanea este QR con Google Authenticator\n(o similar) y luego utiliza el código.", justify="center")
    info.pack(padx=8, pady=(0, 8))

    btn_frame = tk.Frame(win)
    btn_frame.pack(pady=(0, 12))

    def on_close():
        win.destroy()

    close_btn = tk.Button(btn_frame, text="Cerrar", command=on_close)
    close_btn.pack(side="left", padx=6)

    # Hacer modal respecto al parent
    try:
        win.transient(parent)
        win.grab_set()
        parent.wait_window(win)
    except Exception:
        # Si algo falla en grab_set (p. ej. parent no es ventana válida), permitir cierre normal
        pass

    if created_root:
        try:
            parent.destroy()
        except Exception:
            pass

def verificar_codigo(parent=None, prompt="Introduce el código de Google Authenticator:"):
   
    if not os.path.exists(SECRET_FILE):
        messagebox.showwarning("No configurado", "No hay secreto TOTP configurado. Escanea primero el QR.", parent=parent)
        return False

    try:
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            secret = f.read().strip()
    except Exception:
        messagebox.showerror("Error", "No se pudo leer el secreto TOTP.", parent=parent)
        return False

    totp = _get_totp_from_secret(secret)

    codigo = simpledialog.askstring("Verificación", prompt, parent=parent)
    if not codigo:
        # usuario canceló o no introdujo nada
        return False

    try:
        ok = totp.verify(codigo.strip())
    except Exception:
        ok = False

    if not ok:
        messagebox.showerror("Código incorrecto", "El código introducido no es válido.", parent=parent)
        return False

    # éxito
    return True

def mostrar_qr_y_verificar(parent=None, account_name="usuario@ejemplo.com", issuer_name="MiApp"):
    """
    Flujo combinado pensado para usarse al pulsar 'Show' en la app:
    - Si no existe secreto: genera uno, muestra el QR (Toplevel) y luego pide el código.
    - Si existe secreto: solo pide el código.
    Devuelve True si el usuario ha sido verificado con éxito.
    """
    # Si existe secreto: simplemente pedir código
    if os.path.exists(SECRET_FILE):
        return verificar_codigo(parent)

    # Si no existe, generar y mostrar el QR, luego pedir código
    secret, _ = _load_or_generate_secret()
    totp = _get_totp_from_secret(secret)
    uri = totp.provisioning_uri(name=account_name, issuer_name=issuer_name)
    qr_img = qrcode.make(uri)

    # Asegurar parent
    created_root = False
    if parent is None:
        parent = tk.Tk()
        parent.withdraw()
        created_root = True

    win = tk.Toplevel(parent)
    win.title("Escanea el QR y verifica")
    win.resizable(False, False)

    qr_img_resized = qr_img.resize((260, 260))
    qr_photo = ImageTk.PhotoImage(qr_img_resized)

    lbl = tk.Label(win, image=qr_photo)
    lbl.image = qr_photo
    lbl.pack(padx=12, pady=(12, 6))

    info = tk.Label(win, text="Escanea este QR con Google Authenticator.\nDespués pulsa 'Verificar' e introduce el código.", justify="center")
    info.pack(padx=8, pady=(0, 8))

    result = {"ok": False}

    def verificar_callback():
        codigo = simpledialog.askstring("Verificación", "Introduce el código de Google Authenticator:", parent=win)
        if codigo and totp.verify(codigo.strip()):
            messagebox.showinfo("Acceso permitido", "✅ Código correcto, acceso permitido.", parent=win)
            result["ok"] = True
            win.destroy()
        else:
            messagebox.showerror("Acceso denegado", "❌ Código incorrecto. Intenta de nuevo.", parent=win)
            # dejar la ventana abierta para reintentar o cerrar

    btn_frame = tk.Frame(win)
    btn_frame.pack(pady=(0, 12))

    verify_btn = tk.Button(btn_frame, text="Verificar código", command=verificar_callback)
    verify_btn.pack(side="left", padx=6)

    close_btn = tk.Button(btn_frame, text="Cerrar", command=win.destroy)
    close_btn.pack(side="left", padx=6)

    # modal
    try:
        win.transient(parent)
        win.grab_set()
        parent.wait_window(win)
    except Exception:
        pass

    if created_root:
        try:
            parent.destroy()
        except Exception:
            pass

    return result["ok"]

# --- Si se ejecuta directamente, lanzar demo (crea un root) ---
if __name__ == "__main__":
    # Modo demo: muestra QR y luego pide verificar
    root = tk.Tk()
    root.withdraw()
    # Si ya existe secreto, preguntar si quieres reconfigurar
    if os.path.exists(SECRET_FILE):
        if messagebox.askyesno("Reconfigurar?", "Ya existe un secreto. ¿Quieres regenerar y mostrar un QR nuevo?", parent=root):
            try:
                os.remove(SECRET_FILE)
            except Exception:
                pass
            mostrar_qr_y_verificar(parent=root)
        else:
            ok = verificar_codigo(parent=root)
            messagebox.showinfo("Resultado", f"Verificación: {ok}", parent=root)
    else:
        ok = mostrar_qr_y_verificar(parent=root)
        messagebox.showinfo("Resultado", f"Verificación: {ok}", parent=root)
    root.destroy()
