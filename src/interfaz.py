import os
import json
import datetime
import string   
import random
import pyperclip
import customtkinter as ctk
from tkinter import messagebox
import OTP

# Configuración básica (ruta del vault)
VAULT_DIR = os.path.expanduser("~/Documents/UNIVERSIDAD/CIBER/PROYECTO_SEC")
os.makedirs(VAULT_DIR, exist_ok=True)
VAULT_FILE = os.path.join(VAULT_DIR, "Passwords.json")

# ---------- Utilidades (carga/guardado) ----------
def load_entries():
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_entries(entries):
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------- App ----------
class BitwardenLikeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Vault — Gestor de Contraseñas (Bitwarden-like)")
        self.geometry("1000x600")
        self.minsize(900, 560)

        
    

        # Apariencia (claro = blanco + azul)
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        # Datos
        self.entries = load_entries()
        self.filtered_names = []
        self.selected_name = None

        # Apariencia (claro = blanco + azul)
        ctk.set_appearance_mode("light")   # "dark" or "light"
        ctk.set_default_color_theme("blue")

        # Datos
        self.entries = load_entries()   # dict: name -> {Usuario, Contraseña, Notas, Fecha}
        self.filtered_names = []        # lista filtrada para la UI
        self.selected_name = None

        # Layout: sidebar | main
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar (izquierda, oscuro)
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0f1724")
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self._build_sidebar()

        # Main area (centro + derecha)
        self.main = ctk.CTkFrame(self, fg_color="transparent")
        self.main.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        self.main.grid_rowconfigure(1, weight=1)
        self.main.grid_columnconfigure(0, weight=1)
        self._build_main_view()

        # Right detail pane
        self.detail = ctk.CTkFrame(self, width=340, corner_radius=8, fg_color="#3370d3")
        self.detail.grid(row=0, column=2, sticky="nse", padx=(0,12), pady=12)
        self.detail.grid_rowconfigure(8, weight=1)
        self._build_detail_pane()

        # Populate list
        self._refresh_names()
        self._apply_filter()

    # ---------- Sidebar ----------
    def _build_sidebar(self):
        self.logo = ctk.CTkLabel(self.sidebar, text="Vault", font=ctk.CTkFont(size=20, weight="bold"), text_color="white")
        self.logo.pack(padx=16, pady=(18,6), anchor="w")

        subtitle = ctk.CTkLabel(self.sidebar, text="Secured Password Manager", text_color="#cbd5e1")
        subtitle.pack(padx=16, anchor="w")

        # Botones de acción
        self.new_btn = ctk.CTkButton(self.sidebar, text=" + New", fg_color="#1e40af", hover_color="#1b3b92", corner_radius=8, command=self.on_new)
        self.new_btn.pack(padx=16, pady=(18,6), fill="x")

        self.import_btn = ctk.CTkButton(self.sidebar, text=" Import JSON", fg_color="#2563eb", hover_color="#1e4fd3", corner_radius=8, command=self.on_import)
        self.import_btn.pack(padx=16, pady=(0,6), fill="x")

        self.firm_btn = ctk.CTkButton(self.sidebar, text=" Firmar Documento", fg_color="#2563eb", hover_color="#1e4fd3", corner_radius=8, command=self.on_firm)
        self.firm_btn.pack(padx=16, pady=(0,6), fill="x")
         

        # Toggle modo (claro/oscuro)
        toggles_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        toggles_frame.pack(side="bottom", fill="x", pady=16, padx=8)

        self.mode_switch = ctk.CTkSwitch(
            toggles_frame,
            text="Dark mode",
            command=self._toggle_mode,
             progress_color="#2563eb",  # color del slider
             button_color="#60a5fa"
    )
        # Inicializar posición según el modo actual
        self.mode_switch.select() if ctk.get_appearance_mode() == "Dark" else self.mode_switch.deselect()
        self.mode_switch.pack(anchor="w", padx=10, pady=6)
        
        

    def _toggle_mode(self):
        cur = ctk.get_appearance_mode()
        new_mode = "Dark" if cur == "Light" else "Light"
        ctk.set_appearance_mode(new_mode)

    def on_import(self):
        messagebox.showinfo("Importar", "Función de import no implementada en este prototipo.")

    def on_firm(self):
        messagebox.showinfo("FIRMAR", "FIRMAR no definida aun")


    # ---------- Main view (search + list) ----------
    def _build_main_view(self):
        # Top: Search bar
        topbar = ctk.CTkFrame(self.main, fg_color="transparent")
        topbar.grid(row=0, column=0, sticky="ew", pady=(0,8))
        topbar.grid_columnconfigure(1, weight=1)

        tb_label = ctk.CTkLabel(topbar, text="Passwords", font=ctk.CTkFont(size=16, weight="bold"))
        tb_label.grid(row=0, column=0, padx=(6,12), sticky="w")

        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(topbar, placeholder_text="Search by name/username...", textvariable=self.search_var, width=420, corner_radius=10)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0,6))
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filter())

        clear_btn = ctk.CTkButton(topbar, text="Clear", width=70, command=self._clear_search)
        clear_btn.grid(row=0, column=2, padx=(6,0))

        # Center: scrollable list area (cards)
        list_frame = ctk.CTkFrame(self.main, fg_color="transparent")
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.scrollable = ctk.CTkScrollableFrame(list_frame, corner_radius=8, fg_color="transparent")
        self.scrollable.grid(row=0, column=0, sticky="nsew", pady=(0,6))

    def _clear_search(self):
        self.search_var.set("")
        self._apply_filter()

    def _refresh_names(self):
        # refresh internal sorted list of names
        self.filtered_names = sorted(self.entries.keys())

    def _apply_filter(self):
        txt = self.search_var.get().lower().strip()
        # Clear scrollable child widgets
        for w in self.scrollable.winfo_children():
            w.destroy()

        # Filter names
        matched = []
        for name, data in sorted(self.entries.items()):
            if txt == "" or txt in name.lower() or txt in data.get("Usuario", "").lower():
                matched.append((name, data))

        # Create a card (button-like) per entry
        for name, data in matched:
            card = ctk.CTkFrame(self.scrollable, corner_radius=10, fg_color="white", height=70)
            card.pack(fill="x", padx=6, pady=6)

            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

            lbl_name = ctk.CTkLabel(left, text=name, anchor="w", font=ctk.CTkFont(size=12, weight="bold"))
            lbl_name.pack(anchor="w")
            sub = ctk.CTkLabel(left, text=data.get("Usuario", ""), anchor="w", text_color="#475569")
            sub.pack(anchor="w")

            right = ctk.CTkFrame(card, fg_color="transparent")
            right.pack(side="right", padx=10, pady=8)

            # Copy button small
            btn_copy = ctk.CTkButton(right, text="📋", width=40, height=36, fg_color="#60a5fa", hover_color="#3b82f6", corner_radius=8,
                                     command=lambda n=name: self._copy_from_list(n))
            btn_copy.pack()

            # Bind card click to select
            card.bind("<Button-1>", lambda e, n=name: self._select_name(n))
            lbl_name.bind("<Button-1>", lambda e, n=name: self._select_name(n))
            sub.bind("<Button-1>", lambda e, n=name: self._select_name(n))

        # If no matches, show message
        if not matched:
            empty = ctk.CTkLabel(self.scrollable, text="No entries with wanted name", text_color="#64748b")
            empty.pack(pady=12)

    def _copy_from_list(self, name):
        data = self.entries.get(name)
        if data:
            pwd = data.get("Password", "")
            if pwd:
                pyperclip.copy(pwd)
                messagebox.showinfo("Copied", f"Password of '{name}' copied into the clipboard")

    # ---------- Detail pane ----------
    def _build_detail_pane(self):
        # Header
        hdr = ctk.CTkLabel(self.detail, text="Details", font=ctk.CTkFont(size=16, weight="bold"))
        hdr.grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(8,6))

        # Nombre
        lbl = ctk.CTkLabel(self.detail, text="Name", anchor="w")
        lbl.grid(row=1, column=0, sticky="w", padx=12, pady=(6,2))
        self.name_var = ctk.StringVar()
        self.name_entry = ctk.CTkEntry(self.detail, textvariable=self.name_var, width=280, corner_radius=8)
        self.name_entry.grid(row=2, column=0, columnspan=2, padx=12, pady=(0,6))

        # Usuario
        lbl = ctk.CTkLabel(self.detail, text="Username", anchor="w")
        lbl.grid(row=3, column=0, sticky="w", padx=12, pady=(6,2))
        self.user_var = ctk.StringVar()
        self.user_entry = ctk.CTkEntry(self.detail, textvariable=self.user_var, width=280, corner_radius=8)
        self.user_entry.grid(row=4, column=0, columnspan=2, padx=12, pady=(0,6))

        # Contraseña + copy + show
        lbl = ctk.CTkLabel(self.detail, text="Password", anchor="w")
        lbl.grid(row=5, column=0, sticky="w", padx=12, pady=(6,2))
        self.pwd_var = ctk.StringVar()
        self.pwd_entry = ctk.CTkEntry(self.detail, textvariable=self.pwd_var, width=200, corner_radius=8, show="*")
        self.pwd_entry.grid(row=6, column=0, padx=12, pady=(0,6), sticky="w")

        self.show_pwd_var = ctk.BooleanVar(value=False)
        self.show_chk = ctk.CTkCheckBox(self.detail, text="Show", variable=self.show_pwd_var, command=self._toggle_show, corner_radius=10)
        self.show_chk.grid(row=6, column=3, padx=6, pady=(0,6), sticky="w")

        self.reconfig_btn = ctk.CTkButton(
        self.detail,
        text="Random Secured Password",
         fg_color="#0d133c",
        hover_color="#0d094d",
        corner_radius=10,
        command=self._generar_password)
        self.reconfig_btn.grid(row=6, column=1, padx=(12,6), pady=(0,6), sticky="w")


##### RANDOM PASSWORD GENERATOR BUTTON
    def generar_contraseña(self, longitud=15):
        caracteres = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(caracteres) for _ in range(longitud))

    def _generar_password(self):
        nueva_pwd = self.generar_contraseña(15)  # ahora se llama con self
        self.pwd_var.set(nueva_pwd)
        pyperclip.copy(nueva_pwd)
        messagebox.showinfo("Password Generada", "Se ha generado una contraseña segura y copiado al portapapeles.")

######
        # Notas (multilínea)
        lbl = ctk.CTkLabel(self.detail, text="Extra Info", anchor="w")
        lbl.grid(row=7, column=0, sticky="w", padx=12, pady=(6,2))
        self.notes_box = ctk.CTkTextbox(self.detail, width=300, height=120, corner_radius=8)
        self.notes_box.grid(row=8, column=0, columnspan=2, padx=12, pady=(0,6))

        # Fecha (info)
        self.date_label = ctk.CTkLabel(self.detail, text="Last update date: -", text_color="#475569")
        self.date_label.grid(row=9, column=0, columnspan=2, sticky="w", padx=12, pady=(6,4))

        # Action buttons
        action_frame = ctk.CTkFrame(self.detail, fg_color="transparent")
        action_frame.grid(row=10, column=0, columnspan=2, sticky="ew", padx=12, pady=(6,12))
        action_frame.grid_columnconfigure((0,1,2), weight=1)

        self.save_btn = ctk.CTkButton(action_frame, text="Save", fg_color="#0ea5e9", hover_color="#06b6d4", corner_radius=10, command=self.on_save)
        self.save_btn.grid(row=0, column=0, padx=4, sticky="ew")
        self.copy_btn = ctk.CTkButton(action_frame, text="Copy", fg_color="#60a5fa", hover_color="#3b82f6", corner_radius=10, command=self.on_copy)
        self.copy_btn.grid(row=0, column=1, padx=4, sticky="ew")
        self.delete_btn = ctk.CTkButton(action_frame, text="Delete", fg_color="#fb7185", hover_color="#f43f5e", corner_radius=10, command=self.on_delete)
        self.delete_btn.grid(row=0, column=2, padx=4, sticky="ew")

    def _toggle_show(self):
        if self.show_pwd_var.get():
        # Mostrar QR (si es la primera vez) y pedir verificación
            if OTP.mostrar_qr_y_verificar(self):
                self.pwd_entry.configure(show="")
            else:
                self.show_pwd_var.set(False)  # cancelar si falla
                self.pwd_entry.configure(show="*")
        else:
        # Ocultar contraseña
            self.pwd_entry.configure(show="*")


    # ---------- Actions ----------
    def _select_name(self, name):
        # load into detail pane
        self.selected_name = name
        data = self.entries.get(name, {})
        self.name_var.set(name)
        self.user_var.set(data.get("Username", ""))
        self.pwd_var.set(data.get("Password", ""))
        self.notes_box.delete("0.0", "end")
        self.notes_box.insert("0.0", data.get("Notas", ""))
        self.date_label.configure(text=f"Last modification: {data.get('Date','-')}")

    def on_new(self):
        # clear detail pane for new entry
        self.selected_name = None
        self.name_var.set("")
        self.user_var.set("")
        self.pwd_var.set("")
        self.notes_box.delete("0.0", "end")
        self.date_label.configure(text="Last modification: -")

    def on_save(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Aviso", "Name cannot be empty.")
            return
        entry = {
            "Username": self.user_var.get(),
            "Password": self.pwd_var.get(),
            "Extra info": self.notes_box.get("0.0", "end").strip(),
            "FDate": now_iso()
        }
        # If rename (selected_name != name) handle removal of old key
        if self.selected_name and self.selected_name != name:
            if self.selected_name in self.entries:
                del self.entries[self.selected_name]
        self.entries[name] = entry
        save_entries(self.entries)
        self._refresh_names()
        self._apply_filter()
        messagebox.showinfo("Saved", f"'{name}' saved succesfully.")
        self.selected_name = name

    def on_copy(self):
        pwd = self.pwd_var.get()
        if pwd:
            pyperclip.copy(pwd)
            messagebox.showinfo("Copied", "Password copied into clipboard")

    def on_delete(self):
        name = self.name_var.get().strip()
        if not name:
            return
        confirm = messagebox.askyesno("Confirm deleting", f"¿Delete '{name}'?")
        if not confirm:
            return
        if name in self.entries:
            del self.entries[name]
            save_entries(self.entries)
        self.on_new()
        self._refresh_names()
        self._apply_filter()
        messagebox.showinfo("Deleted", f"'{name}' deleted")

# ---------- Run ----------
if __name__ == "__main__":
    app = BitwardenLikeApp()
    app.mainloop()


