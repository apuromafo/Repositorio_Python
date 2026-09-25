#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ------------------------------------------------------------
# DISCLAIMER: Este script es parte del repositorio de herramientas de pruebas de
# penetracion. Su uso esta sujeto a los terminos de la licencia MIT y al aviso
# legal presente en el README.
# ------------------------------------------------------------
# AVISO LEGAL: Uso solo con autorizacion / LEGAL NOTICE: Authorized use only.

"""visor_redaccion v1.3: visor de evidencias "mostrar pero censurar" (GUI).

Para auditorias con datos sensibles (salud, pensiones, PII): abre la captura,
permite marcar regiones con el mouse (barra/blur/pixelado + motivo + color) y
exporta SIEMPRE una copia redactada con hash y manifest. El original nunca se
toca.

PASOS (guiados en pantalla):
  1. Abrir evidencia ............ Boton "Abrir evidencia..." (PNG/JPG/TIFF).
  2. Marcar region sensible ..... Arrastre con boton izquierdo sobre la zona
     (rostro, DNI, nombre, cuerpo, etc.). Sobre la region marcada:
       - Arrastrar DENTRO.............. mover la caja.
       - Arrastrar una ESQUINA......... redimensionarla.
  3. Ajustar .................... En el panel derecho: doble clic en la region
     para cambiar metodo (barra/blur/pixelado), RELLENO y BORDE (color y grosor
     del contorno), intensidad y motivo. Botones para rotar la imagen y guias
     mostrar/ocultar.
  4. Exportar censurado ......... Boton "Exportar censurado" -> copia redactada
     + manifest (trazabilidad) + hash SHA-256 original/salida.
     Boton "Exportar PDF (marca de agua)" -> PDF con la imagen YA redactada y
     con la marca de agua repetida (la evidencia no se puede quitar del PDF).

Ver / ocultar:
  - POR DEFECTO: la vista muestra la version REDACTADA (lo que se exportara).
  - "Ver original" ESTA DESACTIVADO por defecto; quien lo active ve el original
    sin redactar SOLO localmente, con aviso visual.
  - Las guias (rectangulos) se pueden mostrar/ocultar sin afectar el exportado.

Controles extra:
  - Rueda del mouse: zoom. Arrastre con boton derecho: pan.
  - Botones zoom ＋/－/100%/Ajustar en la barra.
  - "✋ Mano (mover vista)": al activarla, arrastrar con boton IZQUIERDO mueve
    la imagen (pan) y NO marca ni censura regiones. Mantener activa al trabajar
    con zoom. Se desactiva para volver a marcar regiones.
  - Botones rotar (90° hor/antihor, 180°): re-mapean las regiones marcadas.
  - "B/N puro": convierte la vista (y la copia exportada, si esta activado) a
    blanco y negro con niveles de gris seleccionables (2/4/8/16/32/64/128/256).
    Util para evidencias a color sin tonos de piel; se registra en el manifest.
  - "Marca PDF:" (campo en la barra, persistente): texto de la marca de agua
    para el export PDF (default CONFIDENCIAL; editable). "Vista previa": la
    muestra en pantalla para verla antes de exportar (opcional, solo visual).
    "Exportar PDF": genera la copia redactada como PDF con la marca repetida
    incrustada (no se puede quitar de la copia publicada). Sin dialogo previo.
  - Tras exportar (PNG o PDF) pregunta si abre la carpeta de salida.

Ejecutar:  python visor_redaccion.py

Privacidad: 100% local (tkinter + Pillow), sin red, sin GPU, sin tokens. Los
casos de auditoria son cerrados y locales; nada se publica.
"""

__version__ = "1.4.0"

import os
import sys

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, colorchooser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import redaccion as rd  # noqa: E402

ZOOM_STEP = 1.2
MIN_ZOOM = 0.05
MAX_ZOOM = 20.0

COLORES = [
    "#000000",  # negro (default)
    "#ffffff",  # blanco
    "#808080",  # gris
    "#c0c0c0",  # plata
    "#ff0000",  # rojo
    "#0000ff",  # azul
    "#ffff00",  # amarillo
    "#00ff00",  # verde
]
COLORES_BORDE = ["sin borde"] + COLORES

PASOS = [
    "1. Abrir evidencia (boton Abrir)",
    "2. Marcar region: arrastra sobre la zona sensible",
    "   -> Sobre la caja: arrastra DENTRO para mover,",
    "      arrastra una ESQUINA para redimensionar",
    "3. Ajustar: doble clic en la region (panel)",
    "   para metodo, COLOR, intensidad y motivo",
    "4. Exportar censurado (boton Exportar)",
]


class VisorRedaccion:
    def __init__(self, root):
        self.root = root
        root.title("Visor de evidencias - mostrar pero censurar (v%s)" % __version__)
        root.geometry("1180x780")

        # estado
        self.pil_orig = None
        self._open_path = None
        self.regiones = []          # lista de dicts {region, modo, color, motivo, intensidad}
        self.mostrar_original = tk.BooleanVar(value=False)   # POR DEFECTO: OCULTO
        self.mostrar_guias = tk.BooleanVar(value=True)
        self.filtro_byn = tk.BooleanVar(value=False)          # B/N puro
        self.niv_byn = tk.StringVar(value="256")
        self.modo_mano = tk.BooleanVar(value=False)          # herramienta MANO (mover vista)
        self.marca_agua = tk.StringVar(value="CONFIDENCIAL") # texto marca PDF (opcion en barra)
        self.vista_previa_marca = tk.BooleanVar(value=False) # vista previa de la marca en canvas
        self.escala = 1.0
        self.offset = (0, 0)
        self._photo = None
        self._sel = None
        self._drag = None            # dict: tipo 'nueva'|'mover'|'redimensionar'
        self._pan_ini = None         # ultimo punto del pan (boton derecho o MANO)
        self._mano_pan = False       # pan activo con boton izquierdo (modo MANO)

        self._build_topbar()
        self._build_main()

    # ---------------------------------------------------------- UI
    def _build_topbar(self):
        caja = ttk.Frame(self.root, padding=(4, 4, 4, 0))
        caja.pack(side="top", fill="x")

        # fila 1: archivo + exportar (PNG y PDF juntos, siempre visibles)
        fila1 = ttk.Frame(caja)
        fila1.pack(side="top", fill="x")
        ttk.Button(fila1, text="Abrir evidencia...", command=self.abrir_imagen).pack(side="left")
        ttk.Button(fila1, text="📷 Exportar PNG", width=13,
                   command=self.exportar).pack(side="left", padx=(6, 0))
        ttk.Button(fila1, text="📄 Exportar PDF", width=13,
                   command=self.exportar_pdf).pack(side="left", padx=(6, 0))

        ttk.Separator(fila1, orient="vertical").pack(side="left", fill="y", padx=8)

        ttk.Label(fila1, text="Marca PDF:").pack(side="left")
        ttk.Entry(fila1, textvariable=self.marca_agua, width=18).pack(side="left", padx=(4, 0))
        ttk.Checkbutton(fila1, text="Vista previa", variable=self.vista_previa_marca,
                        command=self.actualizar_vista).pack(side="left", padx=(6, 0))

        # fila 2: herramientas de edicion/vista
        fila2 = ttk.Frame(caja)
        fila2.pack(side="top", fill="x")

        ttk.Label(fila2, text="Rotar:").pack(side="left")
        ttk.Button(fila2, text="90° ⟲", width=5, command=lambda: self.rotar(90)).pack(side="left", padx=(2, 0))
        ttk.Button(fila2, text="180°", width=5, command=lambda: self.rotar(180)).pack(side="left", padx=(2, 0))
        ttk.Button(fila2, text="90° ⟳", width=5, command=lambda: self.rotar(270)).pack(side="left", padx=(2, 0))

        ttk.Separator(fila2, orient="vertical").pack(side="left", fill="y", padx=8)

        ttk.Checkbutton(fila2, text="B/N puro", variable=self.filtro_byn,
                        command=self.actualizar_vista).pack(side="left")
        ttk.Label(fila2, text="niveles:").pack(side="left", padx=(4, 2))
        self.combo_byn = ttk.Combobox(fila2, textvariable=self.niv_byn,
                                      values=[str(n) for n in rd.NIVELES_BYN],
                                      state="readonly", width=4)
        self.combo_byn.pack(side="left")
        self.combo_byn.bind("<<ComboboxSelected>>", lambda e: self.actualizar_vista())
        self.combo_byn.set("256")

        ttk.Separator(fila2, orient="vertical").pack(side="left", fill="y", padx=8)

        ttk.Checkbutton(fila2, text="Ver ORIGINAL (sin redactar)", variable=self.mostrar_original,
                        command=self.actualizar_vista).pack(side="left")
        ttk.Checkbutton(fila2, text="Guias", variable=self.mostrar_guias,
                        command=self.actualizar_vista).pack(side="left", padx=(8, 0))

        ttk.Separator(fila2, orient="vertical").pack(side="left", fill="y", padx=8)

        ttk.Label(fila2, text="Zoom:").pack(side="left")
        ttk.Button(fila2, text="＋", width=3, command=self._zoom_in).pack(side="left", padx=(2, 0))
        ttk.Button(fila2, text="－", width=3, command=self._zoom_out).pack(side="left", padx=(2, 0))
        ttk.Button(fila2, text="100%", width=5, command=self._zoom_100).pack(side="left", padx=(2, 0))
        ttk.Button(fila2, text="Ajustar", width=7, command=self._zoom_ajustar).pack(side="left", padx=(2, 0))

        ttk.Separator(fila2, orient="vertical").pack(side="left", fill="y", padx=8)

        ttk.Checkbutton(fila2, text="✋ Mano (mover vista)", variable=self.modo_mano,
                        command=self._toggle_mano).pack(side="left")

        # aviso a la derecha de la fila 2 (nunca se corta ni empuja los botones)
        self.lbl_aviso = ttk.Label(fila2, text="")
        self.lbl_aviso.pack(side="right")

    def _build_main(self):
        marco = ttk.PanedWindow(self.root, orient="horizontal")
        marco.pack(fill="both", expand=True)

        cont = ttk.Frame(marco)
        marco.add(cont, weight=4)

        self.canvas = tk.Canvas(cont, bg="#202020", highlightthickness=0)
        vs = ttk.Scrollbar(cont, orient="vertical", command=self.canvas.yview)
        hs = ttk.Scrollbar(cont, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(xscrollcommand=hs.set, yscrollcommand=vs.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        cont.rowconfigure(0, weight=1)
        cont.columnconfigure(0, weight=1)

        self.canvas.bind("<MouseWheel>", self._on_wheel)
        self.canvas.bind("<ButtonPress-2>", self._pan_inicio)
        self.canvas.bind("<B2-Motion>", self._pan_mover)
        self.canvas.bind("<ButtonPress-3>", self._pan_inicio)
        self.canvas.bind("<B3-Motion>", self._pan_mover)
        self.canvas.bind("<ButtonPress-1>", self._press_izq)
        self.canvas.bind("<B1-Motion>", self._mover_izq)
        self.canvas.bind("<ButtonRelease-1>", self._release_izq)
        self.canvas.bind("<Configure>", lambda e: self.actualizar_vista())

        # panel derecho
        lat = ttk.Frame(marco, width=340)
        marco.add(lat, weight=1)

        ttk.Label(lat, text="REGIONES A CENSURAR", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=6, pady=(4, 2))
        cols = ("id", "modo", "motivo")
        self.tree = ttk.Treeview(lat, columns=cols, show="headings", height=12)
        for c, txt, w in (("id", "#", 36), ("modo", "Metodo", 64), ("motivo", "Motivo", 200)):
            self.tree.heading(c, text=txt)
            self.tree.column(c, width=w, anchor="w" if c == "motivo" else "center")
        self.tree.pack(fill="both", expand=True, padx=6, pady=2)
        self.tree.bind("<<TreeviewSelect>>", self._on_seleccion)
        self.tree.bind("<Double-1>", self._editar_seleccion)

        bot = ttk.Frame(lat)
        bot.pack(fill="x", padx=6, pady=4)
        ttk.Button(bot, text="Editar", command=self._editar_seleccion).pack(side="left")
        ttk.Button(bot, text="Eliminar", command=self.eliminar_seleccion).pack(side="left", padx=(6, 0))
        ttk.Button(bot, text="Limpiar todo", command=self.limpiar_todo).pack(side="left", padx=(6, 0))

        ttk.Separator(lat).pack(fill="x", padx=6, pady=(6, 2))
        ttk.Label(lat, text="PASOS", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=6)
        for linea in PASOS:
            ttk.Label(lat, text=linea, foreground="#444", justify="left").pack(anchor="w", padx=10)

        ttk.Separator(lat).pack(fill="x", padx=6, pady=(6, 2))
        info = ("El exportado SIEMPRE sale redactado.\n"
                "'Ver original' es SOLO local y queda\n"
                "apagado por defecto.")
        ttk.Label(lat, text=info, foreground="#555").pack(anchor="w", padx=6, pady=(2, 6))

    # ---------------------------------------------------------- imagen
    def abrir_imagen(self):
        path = filedialog.askopenfilename(
            title="Abrir evidencia",
            filetypes=[("Imagenes", "*.png *.jpg *.jpeg *.tif *.tiff *.bmp"), ("Todos", "*.*")])
        if not path:
            return
        try:
            self.pil_orig = rd.cargar_imagen(path)
            self._open_path = path
        except Exception as exc:
            messagebox.showerror("Error", "No se pudo abrir la imagen:\n%s" % exc)
            return
        self.regiones = []
        self._sel = None
        self.refrescar_lista()
        self._ajustar_zoom()
        self.actualizar_vista()
        self.lbl_aviso.config(text="Cargada: %s" % os.path.basename(path))

    def _ajustar_zoom(self):
        cw = max(self.canvas.winfo_width(), 400)
        ch = max(self.canvas.winfo_height(), 400)
        w, h = self.pil_orig.size
        self.escala = min(cw / w, ch / h, 1.5)
        self.offset = (0, 0)

    def imagen_a_canvas(self, px, py):
        ox, oy = self.offset
        return (px * self.escala + ox), (py * self.escala + oy)

    def canvas_a_imagen(self, cx, cy):
        ox, oy = self.offset
        return (cx - ox) / self.escala, (cy - oy) / self.escala

    def rotar(self, grados):
        """Rota la imagen en memoria y re-mapea las regiones marcadas."""
        if self.pil_orig is None:
            messagebox.showwarning("Aviso", "Abre primero una evidencia.")
            return
        w, h = self.pil_orig.size
        nueva = self.pil_orig.transpose({
            90: __import__("PIL.Image", fromlist=["Image"]).ROTATE_90,
            180: __import__("PIL.Image", fromlist=["Image"]).ROTATE_180,
            270: __import__("PIL.Image", fromlist=["Image"]).ROTATE_270,
        }[grados])
        self.pil_orig = nueva
        # re-mapear regiones a la nueva orientacion
        remapeadas = []
        for reg in self.regiones:
            x1, y1, x2, y2 = list(reg["region"])
            if grados == 90:      # antihorario: (x,y)->(y, W-x)
                reg["region"] = [y1, w - x2, y2, w - x1]
            elif grados == 180:
                reg["region"] = [w - x2, h - y2, w - x1, h - y1]
            elif grados == 270:   # horario: (x,y)->(H-y, x)
                reg["region"] = [h - y2, x1, h - y1, x2]
            remapeadas.append(reg)
        self.regiones = remapeadas
        self._sel = None
        self.refrescar_lista()
        self._ajustar_zoom()
        self.actualizar_vista()

    def _base_vista(self):
        """Imagen PIL que se muestra: redactada (default) u original, con B/N opcional."""
        if self.mostrar_original.get():
            base = self.pil_orig
        else:
            base = rd.aplicar_redaccion(self.pil_orig, self.regiones)
        if self.filtro_byn.get():
            try:
                base = rd.aplicar_byn(base, niveles=int(self.niv_byn.get()))
            except ValueError:
                pass
        return base

    def actualizar_vista(self):
        if self.pil_orig is None:
            return
        base = self._base_vista()
        mostrar_red = not self.mostrar_original.get()

        w, h = base.size
        nw = max(1, int(w * self.escala))
        nh = max(1, int(h * self.escala))
        img = base.resize((nw, nh), __import__("PIL.Image", fromlist=["Image"]).LANCZOS)

        # vista previa opcional de la marca de agua (solo en pantalla, no exporta)
        if self.vista_previa_marca.get() and self.marca_agua.get().strip():
            img = rd.marca_de_agua(img, texto=self.marca_agua.get().strip(), alpha=50)

        from PIL import ImageTk
        self._photo = ImageTk.PhotoImage(img)
        self.canvas.delete("all")
        self.canvas.create_image(self.offset[0], self.offset[1], image=self._photo, anchor="nw")

        if self.modo_mano.get():
            self.lbl_aviso.config(text="MODO MANO: mover la vista; NO marca regiones.",
                                  foreground="#b00020")
        elif self.mostrar_original.get():
            self.lbl_aviso.config(text="!! MOSTRANDO ORIGINAL SIN REDACTAR (solo local)", foreground="#b00000")
        else:
            self.lbl_aviso.config(text="Vista REDACTADA (default) - %d region(es)" % len(self.regiones),
                                  foreground="#006600")

        if self.mostrar_guias.get():
            self._dibujar_guias(w, h, mostrar_red)

        self.canvas.configure(scrollregion=(0, 0, nw + self.offset[0] + 20,
                                            nh + self.offset[1] + 20))

    def _dibujar_guias(self, w, h, mostrar_red):
        base_color = "#00ccff" if mostrar_red else "#ff4040"
        for i, reg in enumerate(self.regiones):
            box = rd.normalizar_region(reg["region"], w, h)
            x1, y1 = self.imagen_a_canvas(*box[:2])
            x2, y2 = self.imagen_a_canvas(*box[2:])
            sel = (i == self._sel)
            color = "#ffd400" if sel else base_color
            width = 3 if sel else 2
            self.canvas.create_rectangle(x1, y1, x2, y2, outline=color, width=width,
                                         tags=("guia", "reg_%d" % i))
            # etiqueta con el numero
            self.canvas.create_text(x1 + 4, y1 + 4, anchor="nw", text=str(i + 1),
                                    fill=color, font=("Segoe UI", 9, "bold"),
                                    tags=("guia", "reg_%d" % i))
            # manijas de redimension en las 4 esquinas (solo visibles al seleccionar)
            if sel:
                for esq, (hx, hy) in (("tl", (x1, y1)), ("tr", (x2, y1)),
                                      ("bl", (x1, y2)), ("br", (x2, y2))):
                    r = 4
                    self.canvas.create_rectangle(hx - r, hy - r, hx + r, hy + r,
                                                 fill="#ffffff", outline="#000000",
                                                 tags=("guia", "handle_%d_%s" % (i, esq)))

    # ---------------------------------------------------------- zoom/pan
    def _zoom_por(self, factor):
        if self.pil_orig is None:
            return
        self.escala = max(MIN_ZOOM, min(MAX_ZOOM, self.escala * factor))
        self.actualizar_vista()

    def _zoom_in(self):
        self._zoom_por(ZOOM_STEP)

    def _zoom_out(self):
        self._zoom_por(1.0 / ZOOM_STEP)

    def _zoom_100(self):
        if self.pil_orig is None:
            return
        self.escala = 1.0
        self.offset = (0, 0)
        self.actualizar_vista()

    def _zoom_ajustar(self):
        if self.pil_orig is None:
            return
        self._ajustar_zoom()
        self.actualizar_vista()

    def _toggle_mano(self):
        """Activa/desactiva la herramienta MANO: arrastrar con boton izquierdo
        mueve la vista (pan) y NO marca ni censura regiones."""
        self.canvas.config(cursor="hand2" if self.modo_mano.get() else "")
        self.actualizar_vista()

    def _on_wheel(self, event):
        if self.pil_orig is None:
            return
        factor = ZOOM_STEP if event.delta > 0 else 1.0 / ZOOM_STEP
        nueva = max(MIN_ZOOM, min(MAX_ZOOM, self.escala * factor))
        ix, iy = self.canvas_a_imagen(event.x, event.y)
        self.escala = nueva
        cx, cy = self.imagen_a_canvas(ix, iy)
        ox, oy = self.offset
        self.offset = (ox + (event.x - cx), oy + (event.y - cy))
        self.actualizar_vista()

    def _pan_inicio(self, event):
        self._pan_ini = (event.x, event.y)

    def _pan_mover(self, event):
        if self._pan_ini is None:
            return
        dx = event.x - self._pan_ini[0]
        dy = event.y - self._pan_ini[1]
        self._pan_ini = (event.x, event.y)
        ox, oy = self.offset
        self.offset = (ox + dx, oy + dy)
        self.actualizar_vista()

    # ---------------------------------------------------------- interaccion izq
    def _item_bajo(self, x, y):
        """Devuelve ('handle', idx, esq) | ('region', idx) | None bajo el cursor."""
        for it in reversed(self.canvas.find_overlapping(x - 3, y - 3, x + 3, y + 3)):
            for tag in self.canvas.gettags(it):
                if tag.startswith("handle_"):
                    _, idx, esq = tag.split("_")
                    return ("handle", int(idx), esq)
                if tag.startswith("reg_"):
                    return ("region", int(tag.split("_")[1]))
        return None

    def _press_izq(self, event):
        if self.pil_orig is None:
            return
        if self.modo_mano.get():
            # herramienta MANO: solo pan, nunca marcar/mover regiones (no censura)
            self._mano_pan = True
            self._pan_inicio(event)
            return
        hit = self._item_bajo(event.x, event.y)
        if hit is None:
            # nueva region
            self._drag = {"tipo": "nueva", "ini": (event.x, event.y)}
            self._drag_rect = self.canvas.create_rectangle(
                event.x, event.y, event.x, event.y,
                outline="#00ff88", width=2, dash=(4, 2))
            return
        tipo, idx, *_ = hit
        if tipo == "handle":
            self._sel = idx
            self._drag = {"tipo": "redimensionar", "idx": idx, "esq": hit[2]}
        else:
            self._sel = idx
            w, h = self.pil_orig.size
            ix, iy = self.canvas_a_imagen(event.x, event.y)
            box = rd.normalizar_region(self.regiones[idx]["region"], w, h)
            self._drag = {"tipo": "mover", "idx": idx,
                          "ini_img": (ix, iy), "ini_box": box}
        self.refrescar_lista()
        self.actualizar_vista()

    def _mover_izq(self, event):
        if self._mano_pan:
            self._pan_mover(event)
            return
        d = self._drag
        if d is None:
            return
        if d["tipo"] == "nueva":
            self.canvas.coords(self._drag_rect, d["ini"][0], d["ini"][1], event.x, event.y)
            return
        w, h = self.pil_orig.size
        if d["tipo"] == "mover":
            ix, iy = self.canvas_a_imagen(event.x, event.y)
            dx = ix - d["ini_img"][0]
            dy = iy - d["ini_img"][1]
            x1, y1, x2, y2 = d["ini_box"]
            self.regiones[d["idx"]]["region"] = [
                max(0, min(w, x1 + dx)), max(0, min(h, y1 + dy)),
                max(0, min(w, x2 + dx)), max(0, min(h, y2 + dy))]
            self.actualizar_vista()
        elif d["tipo"] == "redimensionar":
            ix, iy = self.canvas_a_imagen(event.x, event.y)
            box = list(rd.normalizar_region(self.regiones[d["idx"]]["region"], w, h))
            esq = d["esq"]
            if "l" in esq:
                box[0] = max(0, min(box[2] - 5, int(ix)))
            if "r" in esq:
                box[2] = min(w, max(box[0] + 5, int(ix)))
            if "t" in esq:
                box[1] = max(0, min(box[3] - 5, int(iy)))
            if "b" in esq:
                box[3] = min(h, max(box[1] + 5, int(iy)))
            self.regiones[d["idx"]]["region"] = [float(v) for v in box]
            self.actualizar_vista()

    def _release_izq(self, event):
        if self._mano_pan:
            self._mano_pan = False
            self._pan_ini = None
            return
        if self._drag is None:
            return
        d = self._drag
        self._drag = None
        if d["tipo"] == "nueva":
            if self._drag_rect:
                self.canvas.delete(self._drag_rect)
                self._drag_rect = None
            c1 = self.canvas_a_imagen(*d["ini"])
            c2 = self.canvas_a_imagen(event.x, event.y)
            box = [min(c1[0], c2[0]), min(c1[1], c2[1]),
                   max(c1[0], c2[0]), max(c1[1], c2[1])]
            if box[2] - box[0] < 3 or box[3] - box[1] < 3:
                return
            self._pedir_datos_region(box)
        else:
            self.refrescar_lista()

    # ---------------------------------------------------------- dialogos
    def _pedir_datos_region(self, box, idx=None):
        dlg = tk.Toplevel(self.root)
        dlg.title("Region a censurar" if idx is None else "Editar region")
        dlg.transient(self.root)
        dlg.grab_set()

        prev = self.regiones[idx] if idx is not None else None
        x1, y1, x2, y2 = [int(v) for v in box]

        tk.Label(dlg, text="Region (x1,y1,x2,y2): (%d,%d)-(%d,%d)" % (x1, y1, x2, y2),
                 justify="left").grid(row=0, column=0, columnspan=3, padx=8, pady=4, sticky="w")

        tk.Label(dlg, text="Metodo:").grid(row=1, column=0, padx=8, pady=4, sticky="e")
        modo = ttk.Combobox(dlg, values=list(rd.MODOS), state="readonly", width=16)
        modo.set((prev or {}).get("modo", "barra"))
        modo.grid(row=1, column=1, padx=8, pady=4)

        def _ask(combo_var):
            _, hexc = colorchooser.askcolor(color=combo_var.get(), parent=dlg)
            if hexc:
                combo_var.set(hexc)

        # Relleno (color de la barra)
        tk.Label(dlg, text="Relleno (barra):").grid(row=2, column=0, padx=8, pady=4, sticky="e")
        color_var = tk.StringVar(value=(prev or {}).get("color", "#000000"))
        color_cb = ttk.Combobox(dlg, textvariable=color_var, values=COLORES, width=16)
        color_cb.grid(row=2, column=1, padx=8, pady=4)
        ttk.Button(dlg, text="...", width=3, command=lambda: _ask(color_var)).grid(row=2, column=2, padx=(0, 8))

        # Borde (contorno de la barra; "sin borde" = ninguno)
        tk.Label(dlg, text="Borde (contorno):").grid(row=3, column=0, padx=8, pady=4, sticky="e")
        borde_var = tk.StringVar(value=(prev or {}).get("color_borde") or "sin borde")
        borde_cb = ttk.Combobox(dlg, textvariable=borde_var, values=COLORES_BORDE, width=16)
        borde_cb.grid(row=3, column=1, padx=8, pady=4)
        ttk.Button(dlg, text="...", width=3, command=lambda: _ask(borde_var)).grid(row=3, column=2, padx=(0, 8))

        tk.Label(dlg, text="Grosor borde (px):").grid(row=4, column=0, padx=8, pady=4, sticky="e")
        grosor = ttk.Entry(dlg, width=10)
        grosor.insert(0, str((prev or {}).get("grosor_borde", 2)))
        grosor.grid(row=4, column=1, padx=8, pady=4, sticky="w")

        tk.Label(dlg, text="Motivo:").grid(row=5, column=0, padx=8, pady=4, sticky="e")
        motivo = ttk.Entry(dlg, width=28)
        motivo.insert(0, (prev or {}).get("motivo", ""))
        motivo.grid(row=5, column=1, columnspan=2, padx=8, pady=4, sticky="w")

        tk.Label(dlg, text="Intensidad (blur=radio, pixelado=celda):").grid(row=6, column=0, padx=8, pady=4, sticky="e")
        inten = ttk.Entry(dlg, width=10)
        inten.insert(0, str((prev or {}).get("intensidad", 8)))
        inten.grid(row=6, column=1, padx=8, pady=4, sticky="w")

        def aceptar():
            try:
                intensidad = int(inten.get())
            except ValueError:
                messagebox.showerror("Error", "Intensidad debe ser numerica", parent=dlg)
                return
            try:
                rd._parse_color(color_var.get())
            except ValueError:
                messagebox.showerror("Error", "Relleno invalido: %r" % color_var.get(), parent=dlg)
                return
            borde_val = str(borde_var.get()).strip()
            sin_borde = borde_val.lower() in ("sin borde", "ninguno", "none", "")
            if not sin_borde:
                try:
                    rd._parse_color(borde_val)
                except ValueError:
                    messagebox.showerror("Error", "Borde invalido: %r" % borde_val, parent=dlg)
                    return
            try:
                grosor_val = max(1, int(grosor.get() or 2))
            except ValueError:
                messagebox.showerror("Error", "Grosor de borde debe ser numerico", parent=dlg)
                return
            dato = {
                "region": [float(v) for v in box],
                "modo": modo.get(),
                "color": color_var.get(),
                "color_borde": None if sin_borde else borde_val,
                "grosor_borde": grosor_val,
                "motivo": motivo.get().strip() or "sin motivo",
                "intensidad": intensidad,
            }
            if idx is None:
                self.regiones.append(dato)
                self._sel = len(self.regiones) - 1
            else:
                self.regiones[idx] = dato
                self._sel = idx
            self.refrescar_lista()
            self.actualizar_vista()
            dlg.destroy()

        def cancelar():
            self.actualizar_vista()
            dlg.destroy()

        ttk.Button(dlg, text="Aceptar", command=aceptar).grid(row=7, column=0, pady=8)
        ttk.Button(dlg, text="Cancelar", command=cancelar).grid(row=7, column=1, pady=8)
        motivo.focus_set()

    # ---------------------------------------------------------- lista
    def refrescar_lista(self):
        self.tree.delete(*self.tree.get_children())
        for i, reg in enumerate(self.regiones):
            self.tree.insert("", "end", iid=str(i),
                             values=(i + 1, reg["modo"], reg.get("motivo", "")))
        if self._sel is not None and self.tree.exists(str(self._sel)):
            self.tree.selection_set(str(self._sel))

    def _on_seleccion(self, _event=None):
        sel = self.tree.selection()
        self._sel = int(sel[0]) if sel else None
        self.actualizar_vista()

    def _editar_seleccion(self, _event=None):
        if self._sel is None:
            messagebox.showinfo("Aviso", "Selecciona primero una region en la lista (o en el canvas).")
            return
        w, h = self.pil_orig.size
        box = rd.normalizar_region(self.regiones[self._sel]["region"], w, h)
        self._pedir_datos_region(box, idx=self._sel)

    def eliminar_seleccion(self):
        if self._sel is None:
            return
        del self.regiones[self._sel]
        self._sel = None
        self.refrescar_lista()
        self.actualizar_vista()

    def limpiar_todo(self):
        if self.regiones and messagebox.askyesno("Limpiar", "Quitar todas las regiones?"):
            self.regiones = []
            self._sel = None
            self.refrescar_lista()
            self.actualizar_vista()

    # ---------------------------------------------------------- exportar
    def _abrir_carpeta(self, ruta):
        """Abre la carpeta en el Explorador (Windows)."""
        try:
            import subprocess
            subprocess.Popen(["explorer", ruta])
        except Exception:
            try:
                os.startfile(ruta)
            except Exception:
                pass

    def exportar(self):
        if self.pil_orig is None:
            messagebox.showwarning("Aviso", "Abre primero una evidencia.")
            return
        if not self.regiones:
            messagebox.showwarning("Aviso", "No hay regiones marcadas: nada que censurar.")
            return
        out_dir = filedialog.askdirectory(title="Carpeta de salida (copia redactada)")
        if not out_dir:
            return
        try:
            byn = int(self.niv_byn.get()) if self.filtro_byn.get() else None
            res = rd.redactar_archivo(
                self._open_path,
                self.regiones, out_dir=out_dir,
                filtro_byn=byn,
                comando="visor_redaccion.py (GUI)",
            )
        except Exception as exc:
            messagebox.showerror("Error", "No se pudo exportar:\n%s" % exc)
            return
        msg = ("Exportada copia redactada:\n%s\n\n"
               "manifest: %s\n\n"
               "SHA-256 original: %s\nSHA-256 salida:   %s\n\n"
               "El original NO fue modificado." %
               (res["salida"], res["manifest"], res["hash_original"], res["hash_salida"]))
        messagebox.showinfo("Exportacion OK", msg)
        if messagebox.askyesno("Abrir carpeta", "¿Abrir la carpeta de salida?"):
            self._abrir_carpeta(out_dir)

    def exportar_pdf(self):
        """Exporta la copia redactada como PDF con MARCA DE AGUA sobre la imagen."""
        if self.pil_orig is None:
            messagebox.showwarning("Aviso", "Abre primero una evidencia.")
            return
        if not self.regiones:
            messagebox.showwarning("Aviso", "No hay regiones marcadas: nada que censurar.")
            return
        out_dir = filedialog.askdirectory(title="Carpeta de salida (PDF redactado con marca de agua)")
        if not out_dir:
            return
        texto = (self.marca_agua.get() or "").strip() or "CONFIDENCIAL"
        try:
            byn = int(self.niv_byn.get()) if self.filtro_byn.get() else None
            res = rd.redactar_archivo(
                self._open_path, self.regiones, out_dir=out_dir,
                filtro_byn=byn, pdf=True, marca_agua=texto.strip() or "CONFIDENCIAL",
                comando="visor_redaccion.py (GUI) - PDF marca de agua",
            )
        except Exception as exc:
            messagebox.showerror("Error", "No se pudo exportar el PDF:\n%s" % exc)
            return
        messagebox.showinfo("PDF OK",
                            "PDF redactado con marca de agua:\n%s\n\n"
                            "manifest: %s\n\n"
                            "SHA-256 salida:  %s\n\n"
                            "El original NO fue modificado." %
                            (res["salida_pdf"], res["manifest"], res["hash_salida"]))
        if messagebox.askyesno("Abrir carpeta", "¿Abrir la carpeta de salida?"):
            self._abrir_carpeta(out_dir)


def main():
    root = tk.Tk()
    VisorRedaccion(root)
    root.mainloop()


if __name__ == "__main__":
    main()