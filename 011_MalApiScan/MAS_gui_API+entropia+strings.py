import customtkinter as ctk
from tkinter import filedialog, messagebox
import lief
import json
import os
import threading
import re
import math
from collections import Counter
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class MalApiArchitectGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.author = 'Apuromafo'
        self.version = '0.0.4'
        self.date = '23.06.2025'
        
        self.title(f"MalAPI Scanner v{self.version} - por {self.author}")
        self.geometry("1400x950")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.all_strings = []
        self.report_data = [] 
        self.current_filename = ""
        self.entropy_data = []
        self.raw_binary_data = None
        self.observations = self.load_database()

        self.setup_sidebar()
        self.setup_main_view()

    def load_database(self):
        path = os.path.join(os.path.dirname(__file__), "malapi.json")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)['Categories']
        except: return {}

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="CONTROLES", font=("Consolas", 18, "bold")).pack(pady=20)
        ctk.CTkButton(self.sidebar, text="🔍 Analizar Archivo", command=self.select_file).pack(pady=10, padx=20)
        ctk.CTkButton(self.sidebar, text="💾 Guardar Reporte API", fg_color="#27ae60", command=self.save_formatted_report).pack(pady=5, padx=20)
        ctk.CTkButton(self.sidebar, text="📝 Exportar Strings", fg_color="#2980b9", command=self.save_only_strings).pack(pady=5, padx=20)
        
        # --- CONTROL DE LARGO DE STRINGS (SPINBOX) ---
        ctk.CTkLabel(self.sidebar, text="Largo Mínimo String (1-100):", font=("Consolas", 12)).pack(pady=(20,0))
        
        self.string_len_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.string_len_frame.pack(pady=10)
        
        self.string_len_var = ctk.StringVar(value="6")
        self.btn_sub = ctk.CTkButton(self.string_len_frame, text="-", width=30, command=self.dec_len)
        self.btn_sub.pack(side="left", padx=5)
        
        self.entry_len = ctk.CTkEntry(self.string_len_frame, width=50, textvariable=self.string_len_var, justify="center")
        self.entry_len.pack(side="left", padx=5)
        self.entry_len.bind("<Return>", lambda e: self.reprocess_strings())

        self.btn_add = ctk.CTkButton(self.string_len_frame, text="+", width=30, command=self.inc_len)
        self.btn_add.pack(side="left", padx=5)

        self.progress = ctk.CTkProgressBar(self.sidebar)
        self.progress.pack(pady=20, padx=20)
        self.progress.set(0)

        ctk.CTkLabel(self.sidebar, text="Resumen de Riesgos:", font=("Consolas", 12)).pack(pady=5)
        self.summary_box = ctk.CTkTextbox(self.sidebar, height=250, width=240, font=("Consolas", 11))
        self.summary_box.pack(pady=10, padx=10)

    def setup_main_view(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tab_report = self.tabs.add("Importaciones")
        self.tab_entropy = self.tabs.add("Interpretación de Entropía")
        self.tab_strings = self.tabs.add("Strings")

        # APIs
        self.report_text = ctk.CTkTextbox(self.tab_report, font=("Consolas", 12), wrap="none")
        self.report_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Entropía mejorada
        self.fig, self.ax = plt.subplots(figsize=(6, 3), facecolor='#2b2b2b')
        self.ax.set_facecolor('#2b2b2b')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_entropy)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=5)
        
        self.entropy_info = ctk.CTkTextbox(self.tab_entropy, height=200, font=("Consolas", 12))
        self.entropy_info.pack(fill="x", padx=10, pady=10)

        # Strings
        search_frame = ctk.CTkFrame(self.tab_strings)
        search_frame.pack(fill="x", padx=10, pady=5)
        self.string_search = ctk.CTkEntry(search_frame, placeholder_text="Filtrar en pantalla (ej: http)...", font=("Consolas", 12))
        self.string_search.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.string_search.bind("<KeyRelease>", lambda e: self.update_strings_display())
        
        self.strings_label = ctk.CTkLabel(self.tab_strings, text="Mostrando máximo 1000 cadenas en vista previa.", font=("Consolas", 10), text_color="gray")
        self.strings_label.pack(pady=0)

        self.strings_display = ctk.CTkTextbox(self.tab_strings, font=("Consolas", 12))
        self.strings_display.pack(fill="both", expand=True, padx=10, pady=10)

    def inc_len(self):
        val = int(self.string_len_var.get())
        if val < 100: 
            self.string_len_var.set(str(val + 1))
            self.reprocess_strings()

    def dec_len(self):
        val = int(self.string_len_var.get())
        if val > 1: 
            self.string_len_var.set(str(val - 1))
            self.reprocess_strings()

    def reprocess_strings(self):
        if self.raw_binary_data:
            m_len = int(self.string_len_var.get())
            pattern = re.compile(rb"[\x20-\x7E]{" + str(m_len).encode() + rb",}")
            self.all_strings = [s.decode('ascii', errors='ignore') for s in pattern.findall(self.raw_binary_data)]
            self.update_strings_display()

    def scan_engine(self, path):
        try:
            self.current_filename = os.path.basename(path)
            with open(path, "rb") as f:
                self.raw_binary_data = f.read()
            
            self.reprocess_strings()
            binary = lief.PE.parse(list(self.raw_binary_data))
            if not binary: return

            # APIs
            self.report_data = []
            counts = {cat: 0 for cat in self.observations.keys()}
            total_api = 0
            for imp in binary.imports:
                for entry in imp.entries:
                    tags = [cat for cat, funcs in self.observations.items() if entry.name in funcs]
                    if tags:
                        for t in tags: counts[t] += 1
                        addr = hex(entry.iat_address + binary.imagebase) if entry.iat_address != 0 else "N/A"
                        self.report_data.append([", ".join(tags), addr, entry.name, imp.name])
                        total_api += 1

            # Entropía
            self.entropy_data = []
            max_e = 0
            for sec in binary.sections:
                d = list(sec.content)
                if d:
                    occ = Counter(d)
                    ent = -sum((c/len(d)) * math.log(c/len(d), 2) for c in occ.values())
                    self.entropy_data.append((sec.name.replace('\x00',''), ent))
                    if ent > max_e: max_e = ent

            # Interpretación de Entropía
            interp = f"--- ANÁLISIS DE HEURÍSTICA ---\n"
            interp += f"Entropía Máxima: {max_e:.4f} bits/byte\n"
            if max_e > 7.2:
                interp += "ESTADO: SOSPECHOSO (Alta probabilidad de Empacado o Cifrado)\n"
                interp += "INFO: Valores > 7.0 suelen indicar datos comprimidos como UPX o cifrado personalizado.\n"
            elif max_e > 6.0:
                interp += "ESTADO: NORMAL/ALTO (Código comprimido o recursos grandes)\n"
            else:
                interp += "ESTADO: BAJO/NATIVO (Código plano sin ofuscación aparente)\n"
            
            interp += "\nDetalle por Sección:\n"
            for n, v in self.entropy_data:
                status = " [!] ALTO" if v > 7.1 else ""
                interp += f" > {n:<10}: {v:.4f}{status}\n"

            # Formatear tablas alineadas
            report_body = self.format_as_table(["TAGS", "ADDR", "NAME", "DLL"], self.report_data)
            summary_table = self.format_as_table(["Categoría", "Total"], [[k, v] for k, v in counts.items()])
            
            header = (f"HERRAMIENTA: MalAPI Scanner | AUTOR: {self.author} | VERSION: {self.version}\n"
                      f"ARCHIVO ANALIZADO: {self.current_filename}\n{'='*75}\n")
            
            full_report = f"{header}\n{report_body}\n\nRESUMEN:\n{summary_table}\nTotal APIs Encontradas: {total_api}"
            
            self.after(0, lambda: self.update_ui(full_report, summary_table, interp))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))

    def format_as_table(self, headers, rows):
        if not rows: return ""
        widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row): widths[i] = max(widths[i], len(str(val)))
        h_line = " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
        sep = "-+-".join("-" * w for w in widths)
        return h_line + "\n" + sep + "\n" + "\n".join(" | ".join(f"{str(v):<{widths[i]}}" for i, v in enumerate(row)) for row in rows)

    def update_strings_display(self):
        query = self.string_search.get().lower()
        filtered = [s for s in self.all_strings if query in s.lower()]
        self.strings_display.delete("0.0", "end")
        self.strings_display.insert("0.0", "\n".join(filtered[:1000]))
        if len(filtered) > 1000:
            self.strings_display.insert("end", f"\n\n... [TRUNCADO: {len(filtered)-1000} más ocultos para evitar lag]")

    def update_ui(self, report, summary, interp):
        self.report_text.delete("0.0", "end")
        self.report_text.insert("0.0", report)
        self.summary_box.delete("0.0", "end")
        self.summary_box.insert("0.0", summary)
        self.entropy_info.delete("0.0", "end")
        self.entropy_info.insert("0.0", interp)
        
        self.ax.clear()
        if self.entropy_data:
            n, v = zip(*self.entropy_data)
            self.ax.bar(n, v, color=['#e74c3c' if x > 7.1 else '#2ecc71' for x in v])
            self.ax.set_ylim(0, 8)
            self.ax.axhline(y=7.2, color='white', linestyle='--', alpha=0.3)
            self.ax.tick_params(colors='white', labelsize=8)
            self.canvas.draw()

        self.update_strings_display()
        self.progress.set(1)

    def save_only_strings(self):
        if not self.all_strings: return
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Strings_{self.current_filename}.txt")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"DUMP STRINGS - {self.current_filename} - MinLen: {self.string_len_var.get()}\n\n")
                f.write("\n".join(self.all_strings))
            messagebox.showinfo("Éxito", "Cadenas guardadas.")

    def save_formatted_report(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Reporte_API_{self.current_filename}.txt")
        if p:
            with open(p, "w", encoding="utf-8") as f: f.write(self.report_text.get("0.0", "end"))
            messagebox.showinfo("Éxito", "Reporte guardado.")

    def select_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.progress.set(0.2)
            threading.Thread(target=self.scan_engine, args=(p,), daemon=True).start()

if __name__ == "__main__":
    app = MalApiArchitectGUI()
    app.mainloop()