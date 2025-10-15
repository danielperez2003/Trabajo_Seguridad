# main.py
import sys

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

def autenticar_dnie():
    """Función para autenticar con DNIe"""
    try:
        print("🔐 Iniciando autenticación DNIe...")
        
        # Crear instancia del DNIeManager
        dnie_manager = DNIeManager()
        
        # Solicitar PIN (en una app real esto sería más seguro)
        import getpass
        pin = getpass.getpass("Introduce el PIN de tu DNIe: ")
        
        # Autenticar
        key = dnie_manager.authenticate(pin)
        
        print("✅ Autenticación DNIe exitosa")
        dnie_manager.close()
        return True
        
    except Exception as e:
        print(f"❌ Error en autenticación DNIe: {e}")
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
        # Opción 1: Autenticación real con DNIe (comentado por ahora)
        # if not autenticar_dnie():
        #     print("❌ No se pudo autenticar con DNIe")
        #     sys.exit(1)
        
        # Opción 2: Simular autenticación exitosa para pruebas
        print("⚠️  Modo prueba: Saltando autenticación DNIe")
        print("✅ Acceso concedido - Abriendo interfaz...")
        
        # Abrir interfaz principal
        app = interfaz.BitwardenLikeApp()
        app.mainloop()
        
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
