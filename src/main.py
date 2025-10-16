# main.py - Punto de entrada principal con autenticación DNIe por popup
import sys
import tkinter as tk
from tkinter import simpledialog, messagebox

# --- Fix Tkinter + CustomTkinter float issue ---
try:
    import customtkinter as ctk
    # Sobrescribir función interna para forzar enteros
    original_apply_widget_scaling = ctk.CTkBaseClass._apply_widget_scaling
    def fixed_apply_widget_scaling(self, value):
        return int(original_apply_widget_scaling(self, value))
    ctk.CTkBaseClass._apply_widget_scaling = fixed_apply_widget_scaling
    CTK_AVAILABLE = True
except Exception as e:
    print("No se pudo aplicar workaround de CustomTkinter:", e)
    CTK_AVAILABLE = False

# --- Importar módulos ---
try:
    from dnie import DNIeManager
    DNIE_AVAILABLE = True
except ImportError as e:
    print(f"❌ No se pudo importar dnie.py: {e}")
    DNIE_AVAILABLE = False

try:
    import interfaz
    INTERFAZ_AVAILABLE = True
except ImportError as e:
    print(f"❌ No se pudo importar interfaz.py: {e}")
    INTERFAZ_AVAILABLE = False

def ask_dnie_pin():
    """Solicitar PIN del DNIe mediante popup"""
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal
    
    pin = simpledialog.askstring(
        "PIN del DNIe", 
        "🔐 Introduzca el PIN de su DNIe para acceder al gestor:",
        show='*'
    )
    root.destroy()
    return pin

def autenticar_dnie():
    """Función para autenticar con DNIe usando popup"""
    try:
        print("🔐 Iniciando autenticación DNIe...")
        print("📱 Por favor, inserte su DNIe en el lector...")
        
        # Solicitar PIN mediante popup
        pin = ask_dnie_pin()
        if not pin:
            print("❌ Autenticación cancelada por el usuario")
            return False
        
        # Crear instancia del DNIeManager y autenticar
        dnie_manager = DNIeManager()
        key = dnie_manager.authenticate(pin)
        
        print("✅ Autenticación DNIe exitosa")
        dnie_manager.close()
        return True
        
    except Exception as e:
        messagebox.showerror("Error de autenticación", f"No se pudo autenticar con DNIe:\n\n{str(e)}")
        return False

def main():
    # Verificar dependencias
    if not CTK_AVAILABLE:
        print("❌ CustomTkinter no está disponible")
        sys.exit(1)
    
    if not DNIE_AVAILABLE:
        print("❌ Módulo DNIe no está disponible")
        sys.exit(1)
    
    if not INTERFAZ_AVAILABLE:
        print("❌ Módulo interfaz no está disponible")
        sys.exit(1)
    
    try:
        # Autenticación real con DNIe
        if not autenticar_dnie():
            print("❌ No se pudo autenticar con DNIe. Saliendo...")
            sys.exit(1)
        
        print("✅ Acceso concedido - Abriendo interfaz...")
        
        # Abrir interfaz principal
        app = interfaz.BitwardenLikeApp()
        app.mainloop()
        
    except KeyboardInterrupt:
        print("\n🛑 Operación cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()