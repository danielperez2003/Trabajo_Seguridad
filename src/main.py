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
except Exception as e:
    print("No se pudo aplicar workaround de CustomTkinter:", e)

# --- Importar DNIe ---
try:
    import DNIe
except ImportError:
    print("No se pudo importar DNIe.py")
    sys.exit(1)

# --- Importar interfaz ---
try:
    import interfaz
except ImportError:
    print("No se pudo importar interfaz.py")
    sys.exit(1)


def main():
    try:
        DNIe.main()
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        print("Error inesperado en login DNIe:", e)
        sys.exit(1)

    # Abrir interfaz si PIN correcto
    app = interfaz.BitwardenLikeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
