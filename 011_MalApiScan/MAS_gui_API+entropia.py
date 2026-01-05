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
        self.entropy_data = [] # (nombre_seccion, valor_entropia)

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
        
        self.tab_report = self.tabs.add("Reporte de Importaciones")
        self.tab_entropy = self.tabs.add("Análisis de Entropía")

        # Tab 1: Reporte de APIs
        self.report_text = ctk.CTkTextbox(self.tab_report, font=("Consolas", 12), wrap="none")
        self.report_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 2: Entropía (Gráfico + Texto)
        self.fig, self.ax = plt.subplots(figsize=(8, 4), facecolor='#2b2b2b')
        self.ax.set_facecolor('#2b2b2b')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_entropy)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=5)
        
        self.entropy_info = ctk.CTkTextbox(self.tab_entropy, height=150, font=("Consolas", 12))
        self.entropy_info.pack(fill="x", padx=10, pady=10)

    def format_as_table(self, headers, rows):
        if not rows: return ""
        widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                widths[i] = max(widths[i], len(str(val)))
        
        header_line = " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers))
        separator = "-+-".join("-" * width for width in widths)
        table = [header_line, separator]
        for row in rows:
            table.append(" | ".join(f"{str(v):<{widths[i]}}" for i, v in enumerate(row)))
        return "\n".join(table)

    def calculate_entropy(self, data):
        if not data: return 0
        occ = Counter(data)
        size = len(data)
        return -sum((count/size) * math.log(count/size, 2) for count in occ.values())

    def scan_engine(self, path):
        try:
            self.current_filename = os.path.basename(path)
            binary = lief.PE.parse(path)
            if not binary: return
            
            # 1. Análisis de Importaciones
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

            # 2. Análisis de Entropía por Secciones
            self.entropy_data = []
            max_ent = 0
            for sec in binary.sections:
                e_val = self.calculate_entropy(list(sec.content))
                name = sec.name.replace('\x00', '') or "[?]"
                self.entropy_data.append((name, e_val))
                if e_val > max_ent: max_ent = e_val

            # Formatear Veredicto de Entropía
            verdict = "EMPACADO/CIFRADO POSIBLE" if max_ent > 7.2 else "NATIVO/ESTÁNDAR"
            ent_text = (
                f"--- RESULTADO DE HEURÍSTICA ---\n"
                f"Archivo: {self.current_filename}\n"
                f"Entropía Máxima Detectada: {max_ent:.4f} bits/byte\n"
                f"ESTADO: {verdict}\n\n"
                f"Detalle por Secciones:\n" + 
                "\n".join([f" > {n}: {v:.4f}" for n, v in self.entropy_data])
            )

            # Preparar reporte textual
            report_header = (
                f"HERRAMIENTA: MalAPI Scanner\n"
                f"VERSION: {self.version} | AUTOR: {self.author} | FECHA: {self.date}\n"
                f"ARCHIVO ANALIZADO: {self.current_filename}\n"
                f"{'='*70}\n\n"
            )
            main_table = self.format_as_table(["TAGS", "ADDR", "NAME", "DLL"], self.report_data)
            summary_table = self.format_as_table(["Categoría", "Total"], [[k, v] for k, v in counts.items()])
            
            full_report = f"{report_header}{main_table}\n\nRESUMEN POR CATEGORIAS:\n{summary_table}\n\nTotal: {total_imports}"

            self.after(0, lambda: self.update_ui(full_report, summary_table, ent_text))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))

    def update_ui(self, full_report, summary, entropy_txt):
        # Actualizar Reporte de APIs
        self.report_text.delete("0.0", "end")
        self.report_text.insert("0.0", full_report)
        
        # Actualizar Sidebar
        self.summary_box.delete("0.0", "end")
        self.summary_box.insert("0.0", summary)

        # Actualizar Gráfico de Entropía
        self.ax.clear()
        names, values = zip(*self.entropy_data)
        colors = ['#e74c3c' if v > 7.1 else '#2ecc71' for v in values]
        self.ax.bar(names, values, color=colors)
        self.ax.axhline(y=7.2, color='white', linestyle='--', alpha=0.5)
        self.ax.set_title(f"Mapa de Entropía: {self.current_filename}", color="white")
        self.ax.tick_params(colors='white')
        self.canvas.draw()

        # Actualizar Texto de Heurística
        self.entropy_info.delete("0.0", "end")
        self.entropy_info.insert("0.0", entropy_txt)
        
        self.progress.set(1)

    def save_formatted_report(self):
        if not self.report_data: return
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Análisis_{self.current_filename}.txt")
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(self.report_text.get("0.0", "end"))
                f.write("\n\n" + "="*70 + "\nANÁLISIS DE ENTROPÍA\n" + "="*70 + "\n")
                f.write(self.entropy_info.get("0.0", "end"))
            messagebox.showinfo("Éxito", "Reporte completo guardado.")

    def select_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.progress.set(0.3)
            threading.Thread(target=self.scan_engine, args=(p,), daemon=True).start()

if __name__ == "__main__":
    app = MalApiArchitectGUI()
    app.mainloop()