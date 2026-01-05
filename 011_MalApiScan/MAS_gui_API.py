import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import lief
import json
import os
import threading
import re
from datetime import datetime

class MalApiArchitectGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Metadatos del archivo original
        self.author = 'Apuromafo'
        self.version = '0.0.1'
        self.date = '23.06.2025'
        
        self.title(f"MalAPI Scanner v{self.version} - por {self.author}")
        self.geometry("1400x900")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.report_data = [] 
        self.category_stats = {}
        self.current_filename = ""

        self.setup_sidebar()
        self.setup_main_view()
        self.observations = self.load_database()

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
        ctk.CTkButton(self.sidebar, text="💾 Guardar Reporte", fg_color="#27ae60", command=self.save_formatted_report).pack(pady=10, padx=20)
        
        self.progress = ctk.CTkProgressBar(self.sidebar)
        self.progress.pack(pady=20, padx=20)
        self.progress.set(0)

        ctk.CTkLabel(self.sidebar, text="Resumen de Riesgos:", font=("Consolas", 12)).pack(pady=5)
        self.summary_box = ctk.CTkTextbox(self.sidebar, height=300, width=240, font=("Consolas", 11))
        self.summary_box.pack(pady=10, padx=10)

    def setup_main_view(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.tab_report = self.tabs.add("Reporte de Análisis")
        self.report_text = ctk.CTkTextbox(self.tab_report, font=("Consolas", 12), wrap="none")
        self.report_text.pack(fill="both", expand=True, padx=10, pady=10)

    def format_as_table(self, headers, rows):
        """Réplica de la función print_table original"""
        if not rows: return ""
        widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                widths[i] = max(widths[i], len(str(val)))
        
        header_line = " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
        separator = "-+-".join("-" * w for w in widths)
        table = [header_line, separator]
        for row in rows:
            table.append(" | ".join(f"{str(v):<{widths[i]}}" for i, v in enumerate(row)))
        return "\n".join(table)

    def scan_engine(self, path):
        try:
            self.current_filename = os.path.basename(path)
            binary = lief.PE.parse(path)
            if not binary: return
            
            self.report_data = []
            counts = {cat: 0 for cat in self.observations.keys()}
            total_imports = 0
            
            for imp in binary.imports:
                for entry in imp.entries:
                    tags = [cat for cat, funcs in self.observations.items() if entry.name in funcs]
                    if tags:
                        for t in tags: counts[t] += 1
                        addr = hex(entry.iat_address + binary.imagebase) if entry.iat_address != 0 else "N/A"
                        self.report_data.append([", ".join(tags), addr, entry.name, imp.name])
                        total_imports += 1

            self.category_stats = counts
            
            # Generar el texto del reporte con encabezado completo
            report_header = (
                f"HERRAMIENTA: MalAPI Scanner\n"
                f"VERSION: {self.version} | AUTOR: {self.author} | FECHA: {self.date}\n"
                f"ARCHIVO ANALIZADO: {self.current_filename}\n"
                f"{'='*70}\n\n"
            )
            
            main_table = self.format_as_table(["TAGS", "ADDR", "NAME", "DLL"], self.report_data)
            
            summary_list = [[k, v] for k, v in counts.items()]
            summary_table = self.format_as_table(["Categoría", "Total"], summary_list)
            
            final_text = (
                f"{report_header}"
                f"{main_table}\n\n"
                f"RESUMEN POR CATEGORIAS:\n{summary_table}\n\n"
                f"Total de funciones importadas encontradas: {total_imports}"
            )

            self.after(0, lambda: self.update_ui(final_text, summary_table, total_imports))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Error: {str(e)}"))

    def update_ui(self, full_report, summary, total):
        self.report_text.delete("0.0", "end")
        self.report_text.insert("0.0", full_report)
        self.summary_box.delete("0.0", "end")
        self.summary_box.insert("0.0", summary)
        self.progress.set(1)

    def save_formatted_report(self):
        if not self.report_data: return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Reporte_{self.current_filename}.txt")
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(self.report_text.get("0.0", "end"))
            messagebox.showinfo("Éxito", "Reporte guardado con éxito.")

    def select_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.progress.set(0.3)
            threading.Thread(target=self.scan_engine, args=(p,), daemon=True).start()

if __name__ == "__main__":
    app = MalApiArchitectGUI()
    app.mainloop()