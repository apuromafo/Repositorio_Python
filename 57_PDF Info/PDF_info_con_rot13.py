#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script: pdf_analyzer_pro_complete.py
Versión: 3.3.0
Autor: Pentester Tool
Fecha: 2025-10-07
Descripción: Análisis completo de PDF con detección de malware y Canary Tokens
Cambios v3.3.0:
    - Patrones de detección ofuscados con ROT13 en código fuente
    - Decodificación automática en runtime
    - Protección contra análisis del código
"""

import argparse
import os
import sys
import hashlib
import json
import re
import logging
import zlib
import codecs
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    from pypdf import PdfReader, PasswordType
    from pypdf.generic import EncodedStreamObject, DictionaryObject, IndirectObject
except ImportError:
    print("❌ ERROR: La librería 'pypdf' no está instalada.")
    print("Ejecuta: pip install pypdf")
    sys.exit(1)

# --- CONFIGURACIÓN Y CONSTANTES ---
VERSION = "3.3.0"

# --- FUNCIONES DE DECODIFICACIÓN ---

def _d(s: str) -> str:
    """Decodifica strings ofuscados (ROT13)"""
    return codecs.decode(s, 'rot_13')


# Patrones de Canary Tokens OFUSCADOS con ROT13
_CANARY_PATTERNS = [
    (r'pnanelgbxraf\.(pbz|bet|arg)', 'Pnanel Gbxra Bsvpvny', 100),
    (r'arebfjnez\.pbz/ubarl', 'Ubarl Gbxra', 100),
    (r'guvaxfg\.pbz/pnanel', 'Guvaxfg Pnanel', 100),
    (r'pnanel\.gbbyf', 'Pnanel Gbbyf', 100),
]

# Servicios de tracking OFUSCADOS
_TRACKING = {
    'ovg.yl': {'evbfxb': 'ZRQVB', 'chagbf': 30, 'gvcb': 'HEY Fubegrate'},
    'gvaληey.pbz': {'evbfxb': 'ZRQVB', 'chagbf': 30, 'gvcb': 'HEY Fubegrate'},
    'eroenayl.pbz': {'evbfxb': 'ZRQVB', 'chagbf': 35, 'gvcb': 'HEY Fubegrate Ceb'},
    'znvygenpx.vb': {'evbfxb': 'NYGB', 'chagbf': 60, 'gvcb': 'Rznvy Genpxvat'},
    'lrfjner.pbz': {'evbfxb': 'NYGB', 'chagbf': 60, 'gvcb': 'Rznvy Genpxvat'},
    'uhofcbg.pbz': {'evbfxb': 'ZRQVB', 'chagbf': 40, 'gvcb': 'Znexrgvat Genpxvat'},
    'fnyrsbepr.pbz': {'evbfxb': 'ZRQVB', 'chagbf': 40, 'gvcb': 'PEZ Genpxvat'},
    'tbbtyr-nanylgvpf.pbz': {'evbfxb': 'ZRQVB', 'chagbf': 35, 'gvcb': 'Nanylgvpf'},
    'qbhoyrpyvpx.arg': {'evbfxb': 'ZRQVB', 'chagbf': 35, 'gvcb': 'Nq Genpxvat'},
    'zvkcnary.pbz': {'evbfxb': 'ZRQVB', 'chagbf': 40, 'gvcb': 'Nanylgvpf'},
}

# Patrones sospechosos OFUSCADOS
_SUSPICIOUS_PATTERNS = [
    (r'/fhozrg\.nfck', 'Fhozrg raqcbvag (pbzúa ra pnanel gbxraf)', 40),
    (r'/ncv/ornpba', 'Ornpba NCV raqcbvag', 50),
    (r'/genpx/', 'Genpx raqcbvag', 45),
    (r'/cvkry\.', 'Genpxvat cvkry', 50),
    (r'/bcra/', 'Bcra genpxvat', 45),
    (r'/pyvpx/', 'Pyvpx genpxvat', 40),
    (r'\?vq=[n-s0-9]{20,}', 'Ybat genpxvat VQ', 35),
    (r'/[N-M]{25,}', 'Gbxra-yvxr hccrePnfr cngu', 30),
]

# Dominios legítimos OFUSCADOS
_IGNORED = [
    'fpurznf.bcraxzysbezngf.bet',
    'fpurznf.zvpebfbsg.pbz',
    'chevy.bet',
    'j3.bet',
    'kzyyaf.pbz',
    'zvpebfbsg.pbz/bssvpr',
    'af.nqbor.pbz',
]

# DECODIFICAR TODO AL INICIO
def _init_patterns():
    """Inicializa patrones decodificando ROT13"""
    global CANARY_TOKEN_PATTERNS, TRACKING_SERVICES, SUSPICIOUS_URL_PATTERNS, IGNORED_DOMAINS
    
    # Decodificar patrones de Canary Tokens
    CANARY_TOKEN_PATTERNS = [
        (_d(patron), _d(tipo), puntos) 
        for patron, tipo, puntos in _CANARY_PATTERNS
    ]
    
    # Decodificar servicios de tracking
    TRACKING_SERVICES = {
        _d(dominio): {
            _d(k): _d(v) if isinstance(v, str) else v 
            for k, v in info.items()
        }
        for dominio, info in _TRACKING.items()
    }
    
    # Decodificar patrones sospechosos
    SUSPICIOUS_URL_PATTERNS = [
        (_d(patron), _d(desc), puntos) 
        for patron, desc, puntos in _SUSPICIOUS_PATTERNS
    ]
    
    # Decodificar dominios ignorados
    IGNORED_DOMAINS = [_d(d) for d in _IGNORED]


# Inicializar patrones decodificados
_init_patterns()

# Objetos sospechosos en PDFs (estos no se ofuscan, son estándar PDF)
SUSPICIOUS_KEYWORDS = [
    '/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch', 
    '/SubmitForm', '/URI', '/GoToR', '/ImportData', '/EmbeddedFile',
    '/XFA', '/RichMedia', '/XObject'
]

# Flags de permisos
PERMISSIONS_FLAGS = {
    3: "Imprimir en baja resolución",
    4: "Modificar el documento",
    5: "Copiar o extraer texto e imágenes",
    6: "Añadir o modificar comentarios/campos",
    9: "Imprimir en alta resolución",
    10: "Rellenar campos existentes y firmar",
    11: "Extraer páginas",
    12: "Ensamblar documento"
}

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# --- CLASES AUXILIARES ---

class URLAnalyzer:
    """Analiza URLs y detecta Canary Tokens y servicios de tracking"""
    
    @staticmethod
    def extraer_token_id(url: str) -> Optional[str]:
        """Extrae el Token ID de una URL de Canary Token"""
        match = re.search(r'([a-z0-9]{15,})\.canarytokens\.(com|org|net)', url, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    @staticmethod
    def analizar_url(url: str) -> Dict:
        """Analiza una URL y determina si es un Canary Token o servicio de tracking"""
        resultado = {
            'url': url,
            'es_canary_token': False,
            'token_id': None,
            'es_tracking': False,
            'servicio': 'Desconocido',
            'tipo': 'URL Externa',
            'riesgo': 'BAJO',
            'puntuacion': 10,
            'razones': []
        }
        
        url_lower = url.lower()
        
        # Verificar si debe ser ignorada
        for dominio in IGNORED_DOMAINS:
            if dominio in url_lower:
                resultado['riesgo'] = 'IGNORADO'
                resultado['puntuacion'] = 0
                resultado['tipo'] = 'Dominio Legítimo (Esquema/Metadatos)'
                return resultado
        
        # Verificar Canary Tokens con patrones decodificados
        for patron, tipo, puntos in CANARY_TOKEN_PATTERNS:
            if re.search(patron, url_lower):
                resultado['es_canary_token'] = True
                resultado['servicio'] = re.search(patron, url_lower).group(0)
                resultado['tipo'] = tipo
                resultado['riesgo'] = 'CRÍTICO'
                resultado['puntuacion'] = puntos
                resultado['razones'].append(f'🚨 CANARY TOKEN DETECTADO: {tipo}')
                
                # Extraer Token ID si es canarytokens
                if 'canarytokens' in url_lower:
                    token_id = URLAnalyzer.extraer_token_id(url)
                    if token_id:
                        resultado['token_id'] = token_id
                        resultado['razones'].append(f'Token ID: {token_id}')
                
                return resultado
        
        # Verificar servicios de tracking decodificados
        for dominio, info in TRACKING_SERVICES.items():
            if dominio in url_lower:
                resultado['es_tracking'] = True
                resultado['servicio'] = dominio
                resultado['tipo'] = info['tipo']
                resultado['riesgo'] = info['riesgo']
                resultado['puntuacion'] = info['puntos']
                resultado['razones'].append(f'Servicio de tracking: {info["tipo"]}')
        
        # Verificar patrones sospechosos decodificados
        for patron, descripcion, puntos in SUSPICIOUS_URL_PATTERNS:
            if re.search(patron, url, re.IGNORECASE):
                resultado['razones'].append(descripcion)
                resultado['puntuacion'] += puntos
                if resultado['riesgo'] == 'BAJO':
                    resultado['riesgo'] = 'MEDIO'
        
        # Ajustar riesgo basado en puntuación
        if resultado['puntuacion'] >= 80 and not resultado['es_canary_token']:
            resultado['riesgo'] = 'ALTO'
        elif resultado['puntuacion'] >= 50:
            resultado['riesgo'] = 'MEDIO'
        
        return resultado


class RiesgoCalculador:
    """Calcula el nivel de riesgo del PDF basado en características sospechosas"""
    
    @staticmethod
    def calcular_puntuacion(info: Dict) -> Tuple[int, str, List[str]]:
        """Retorna: (puntuacion, nivel, razones)"""
        puntuacion = 0
        razones = []
        
        # CANARY TOKENS - MÁXIMA PRIORIDAD
        if info.get('urls_analizadas'):
            canary_tokens = [u for u in info['urls_analizadas'] if u['es_canary_token']]
            if canary_tokens:
                puntuacion = 100
                razones.append(f"🚨 CANARY TOKEN DETECTADO: {len(canary_tokens)} token(s)")
                
                for token in canary_tokens:
                    if token.get('token_id'):
                        razones.append(f"   └─ Token ID: {token['token_id']}")
                
                return (100, "🔴 CRÍTICO - CANARY TOKEN", razones)
        
        # JavaScript presente
        if info.get('tiene_javascript'):
            puntuacion += 30
            razones.append("Contiene JavaScript ejecutable")
        
        # Archivos embebidos
        if info.get('archivos_embebidos'):
            puntuacion += 25
            razones.append(f"Contiene {len(info['archivos_embebidos'])} archivo(s) embebido(s)")
        
        # Acciones automáticas sospechosas
        acciones = info.get('acciones_automaticas', {})
        if acciones.get('tiene_openaction'):
            puntuacion += 20
            razones.append("Ejecuta acciones al abrir (OpenAction)")
        
        if acciones.get('tiene_launch'):
            puntuacion += 35
            razones.append("Intenta ejecutar programas externos (/Launch)")
        
        if acciones.get('tiene_uri'):
            puntuacion += 15
            razones.append("Contiene enlaces externos a URLs")
        
        # Servicios de tracking
        if info.get('urls_analizadas'):
            tracking = [u for u in info['urls_analizadas'] if u['es_tracking']]
            if tracking:
                puntuacion += 20
                razones.append(f"Contiene {len(tracking)} servicio(s) de tracking")
        
        # URLs externas (sin contar las ignoradas)
        urls_reales = [u for u in info.get('urls_analizadas', []) if u['riesgo'] != 'IGNORADO']
        if urls_reales and len(urls_reales) > 5:
            puntuacion += 10
            razones.append(f"Contiene {len(urls_reales)} URLs externas")
        
        # Formularios que envían datos
        if acciones.get('tiene_submitform'):
            puntuacion += 25
            razones.append("Formulario que envía datos externos")
        
        # Encriptación con restricciones
        if info.get('restricciones_uso', {}).get('encriptado'):
            if not info['restricciones_uso'].get('puede_copiar'):
                puntuacion += 5
                razones.append("Restricción de copia de contenido")
        
        # Determinar nivel
        if puntuacion >= 70:
            nivel = "🔴 CRÍTICO"
        elif puntuacion >= 50:
            nivel = "🟠 ALTO"
        elif puntuacion >= 30:
            nivel = "🟡 MEDIO"
        elif puntuacion >= 10:
            nivel = "🟢 BAJO"
        else:
            nivel = "✅ MÍNIMO"
        
        return min(puntuacion, 100), nivel, razones


class ExtraerURLs:
    """Extrae URLs de objetos PDF usando múltiples métodos"""
    
    @staticmethod
    def extraer_de_streams(pdf_content: bytes) -> List[str]:
        """Extrae URLs de streams comprimidos (FlateDecode)"""
        urls = set()
        
        # Buscar streams comprimidos
        streams = re.findall(rb'stream[\r\n\s]+(.*?)[\r\n\s]+endstream', pdf_content, re.DOTALL)
        
        for stream in streams:
            # Intentar descomprimir
            try:
                decompressed_data = zlib.decompress(stream)
                urls_bytes = re.findall(rb'https?://[^\s<>"\'{}|\\^`\[\]\)]+', decompressed_data)
                for url in urls_bytes:
                    urls.add(url.decode('utf-8', 'ignore'))
            except zlib.error:
                # Si no está comprimido, buscar directamente
                try:
                    urls_bytes = re.findall(rb'https?://[^\s<>"\'{}|\\^`\[\]\)]+', stream)
                    for url in urls_bytes:
                        urls.add(url.decode('utf-8', 'ignore'))
                except:
                    pass
        
        return list(urls)
    
    @staticmethod
    def extraer_de_anotaciones(reader: PdfReader) -> List[str]:
        """Extrae URLs de anotaciones y acciones URI"""
        urls = set()
        
        for page in reader.pages:
            if '/Annots' in page:
                try:
                    annots = page['/Annots']
                    for annot in annots:
                        annot_obj = annot.get_object() if isinstance(annot, IndirectObject) else annot
                        if '/A' in annot_obj and '/URI' in annot_obj['/A']:
                            uri = annot_obj['/A']['/URI']
                            if isinstance(uri, str):
                                urls.add(uri)
                except:
                    pass
        
        return list(urls)
    
    @staticmethod
    def extraer_del_pdf(reader: PdfReader, pdf_content: bytes) -> List[str]:
        """Extrae todas las URLs del PDF usando múltiples técnicas"""
        urls = set()
        
        # Método 1: Anotaciones
        urls.update(ExtraerURLs.extraer_de_anotaciones(reader))
        
        # Método 2: Streams comprimidos
        urls.update(ExtraerURLs.extraer_de_streams(pdf_content))
        
        # Método 3: Texto plano en todo el PDF
        urls_plaintext = re.findall(rb'https?://[^\s<>"\'{}|\\^`\[\]\)]+', pdf_content)
        for url in urls_plaintext:
            urls.add(url.decode('utf-8', 'ignore'))
        
        # Método 4: Catálogo y objetos del PDF
        try:
            root = reader.trailer.get("/Root")
            if root:
                root_str = str(root)
                url_pattern = re.compile(r'https?://[^\s<>"\'\\)]+')
                found = url_pattern.findall(root_str)
                urls.update(found)
        except:
            pass
        
        return list(urls)


class ArchivosEmbebidos:
    """Maneja la extracción de archivos embebidos"""
    
    @staticmethod
    def extraer_info(reader: PdfReader) -> List[Dict]:
        """Extrae información de archivos embebidos"""
        embebidos = []
        
        try:
            root = reader.trailer.get("/Root")
            if not root:
                return embebidos
            
            if "/Names" in root:
                names = root["/Names"]
                if "/EmbeddedFiles" in names:
                    ef_tree = names["/EmbeddedFiles"]
                    if "/Names" in ef_tree:
                        names_array = ef_tree["/Names"]
                        
                        for i in range(0, len(names_array), 2):
                            if i + 1 < len(names_array):
                                nombre = names_array[i]
                                filespec = names_array[i + 1]
                                
                                if isinstance(filespec, IndirectObject):
                                    filespec = filespec.get_object()
                                
                                if isinstance(filespec, DictionaryObject) and "/EF" in filespec:
                                    ef_dict = filespec["/EF"]
                                    if "/F" in ef_dict:
                                        file_stream = ef_dict["/F"]
                                        if isinstance(file_stream, IndirectObject):
                                            file_stream = file_stream.get_object()
                                        
                                        info_embebido = {
                                            'nombre': str(nombre),
                                            'tamano': len(file_stream.get_data()) if hasattr(file_stream, 'get_data') else 0,
                                            'tipo': str(filespec.get('/Subtype', 'Desconocido'))
                                        }
                                        embebidos.append(info_embebido)
        except Exception as e:
            logger.debug(f"Error extrayendo archivos embebidos: {e}")
        
        return embebidos
    
    @staticmethod
    def guardar_embebidos(reader: PdfReader, ruta_pdf: str, directorio_salida: str = None):
        """Guarda archivos embebidos en disco"""
        if directorio_salida is None:
            directorio_salida = os.path.splitext(ruta_pdf)[0] + "_embebidos"
        
        Path(directorio_salida).mkdir(parents=True, exist_ok=True)
        archivos_guardados = []
        
        try:
            root = reader.trailer.get("/Root")
            if root and "/Names" in root:
                names = root["/Names"]
                if "/EmbeddedFiles" in names:
                    ef_tree = names["/EmbeddedFiles"]
                    if "/Names" in ef_tree:
                        names_array = ef_tree["/Names"]
                        
                        for i in range(0, len(names_array), 2):
                            if i + 1 < len(names_array):
                                nombre = str(names_array[i])
                                filespec = names_array[i + 1]
                                
                                if isinstance(filespec, IndirectObject):
                                    filespec = filespec.get_object()
                                
                                if isinstance(filespec, DictionaryObject) and "/EF" in filespec:
                                    ef_dict = filespec["/EF"]
                                    if "/F" in ef_dict:
                                        file_stream = ef_dict["/F"]
                                        if isinstance(file_stream, IndirectObject):
                                            file_stream = file_stream.get_object()
                                        
                                        ruta_guardado = os.path.join(directorio_salida, nombre)
                                        with open(ruta_guardado, 'wb') as f:
                                            f.write(file_stream.get_data())
                                        
                                        archivos_guardados.append(ruta_guardado)
                                        logger.info(f"  > Archivo embebido guardado: {ruta_guardado}")
        except Exception as e:
            logger.error(f"Error guardando archivos embebidos: {e}")
        
        return archivos_guardados


# --- FUNCIONES DE UTILIDAD ---

def calcular_hash_y_tamano(ruta: str) -> Dict:
    """Calcula SHA256, MD5 y tamaño del archivo"""
    hash_info = {'sha256': 'N/A', 'md5': 'N/A', 'tamano_bytes': 0}
    
    if not os.path.exists(ruta):
        return hash_info

    try:
        hash_info['tamano_bytes'] = os.path.getsize(ruta)
        hasher_sha256 = hashlib.sha256()
        hasher_md5 = hashlib.md5()
        
        with open(ruta, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher_sha256.update(chunk)
                hasher_md5.update(chunk)
                
        hash_info['sha256'] = hasher_sha256.hexdigest()
        hash_info['md5'] = hasher_md5.hexdigest()
    
    except Exception as e:
        logger.warning(f"No se pudo calcular hash/tamaño: {e}")
        
    return hash_info


def guardar_texto_en_txt(ruta_pdf: str, texto_completo: str):
    """Guarda el texto extraído del PDF"""
    ruta_txt = os.path.splitext(ruta_pdf)[0] + "_contenido.txt"
    
    try:
        with open(ruta_txt, 'w', encoding='utf-8') as f:
            f.write(texto_completo)
        logger.info(f"  > Texto guardado en: {ruta_txt}")
    except Exception as e:
        logger.error(f"Error al guardar TXT: {e}")


def buscar_javascript(reader: PdfReader) -> List[str]:
    """Busca y extrae código JavaScript"""
    javascript_snippets = []
    
    try:
        root = reader.trailer.get("/Root")
        if root and "/Names" in root:
            names_tree = root["/Names"]
            if "/JavaScript" in names_tree:
                js_names = names_tree["/JavaScript"]
                if "/Names" in js_names:
                    js_array = js_names["/Names"]
                    for i in range(1, len(js_array), 2):
                        js_ref = js_array[i]
                        js_obj = js_ref.get_object() if isinstance(js_ref, IndirectObject) else js_ref
                        
                        if isinstance(js_obj, DictionaryObject) and "/JS" in js_obj:
                            js_action = js_obj["/JS"]
                            if isinstance(js_action, EncodedStreamObject):
                                js_source = js_action.get_data().decode('utf-8', errors='ignore')
                            else:
                                js_source = str(js_action)
                            javascript_snippets.append(js_source)
    except Exception as e:
        logger.debug(f"Error buscando JavaScript: {e}")
    
    return javascript_snippets


def analizar_acciones_automaticas(reader: PdfReader) -> Dict:
    """Analiza acciones automáticas y objetos sospechosos"""
    acciones = {
        'tiene_openaction': False,
        'tiene_aa': False,
        'tiene_launch': False,
        'tiene_uri': False,
        'tiene_submitform': False,
        'tiene_importdata': False,
        'detalles_openaction': 'Ninguno',
        'objetos_sospechosos': []
    }
    
    try:
        root = reader.trailer.get("/Root")
        if not root:
            return acciones
        
        # Verificar OpenAction
        if "/OpenAction" in root:
            acciones['tiene_openaction'] = True
            open_action = root["/OpenAction"]
            if isinstance(open_action, IndirectObject):
                open_action = open_action.get_object()
            acciones['detalles_openaction'] = str(open_action)[:200]
            acciones['objetos_sospechosos'].append('/OpenAction detectado')
        
        # Verificar AA (Additional Actions)
        if "/AA" in root:
            acciones['tiene_aa'] = True
            acciones['objetos_sospechosos'].append('/AA (Additional Actions) detectado')
        
        # Buscar en todas las páginas
        for page_num, page in enumerate(reader.pages):
            if "/Launch" in page:
                acciones['tiene_launch'] = True
                acciones['objetos_sospechosos'].append(f'/Launch en página {page_num + 1}')
            
            if "/Annots" in page:
                try:
                    annots = page["/Annots"]
                    for annot in annots:
                        annot_obj = annot.get_object() if isinstance(annot, IndirectObject) else annot
                        if "/A" in annot_obj:
                            action = annot_obj["/A"]
                            if isinstance(action, IndirectObject):
                                action = action.get_object()
                            
                            if "/URI" in action:
                                acciones['tiene_uri'] = True
                            if "/Launch" in action:
                                acciones['tiene_launch'] = True
                            if "/S" in action and action["/S"] == "/SubmitForm":
                                acciones['tiene_submitform'] = True
                            if "/S" in action and action["/S"] == "/ImportData":
                                acciones['tiene_importdata'] = True
                except:
                    pass
    
    except Exception as e:
        logger.debug(f"Error analizando acciones: {e}")
    
    return acciones


def intentar_desencriptar(reader: PdfReader) -> bool:
    """Maneja la desencriptación interactiva"""
    print("\n[🔒 ENCRIPTACIÓN DETECTADA 🔒]")
    
    intentos = 0
    while intentos < 3: 
        respuesta = input("¿Desea ingresar la contraseña para desencriptar? (s/n): ").lower()
        
        if respuesta == 'n':
            logger.info("Extracción cancelada por el usuario.")
            return False
        
        if respuesta == 's':
            password = input("Ingrese la contraseña: ")
            try:
                resultado = reader.decrypt(password)
                
                if resultado in (PasswordType.OWNER_PASSWORD, PasswordType.USER_PASSWORD):
                    print("✅ Contraseña correcta. Documento desencriptado.")
                    return True
                else:
                    print("❌ Contraseña incorrecta. Intente de nuevo.")
                    intentos += 1
            except Exception as e:
                print(f"❌ Error al intentar desencriptar: {e}. Intente de nuevo.")
                intentos += 1
        else:
            print("Respuesta no válida. Por favor, ingrese 's' o 'n'.")
            
    print("Número máximo de intentos alcanzado. Extracción cancelada.")
    return False


def obtener_permisos(reader: PdfReader) -> Dict:
    """Extrae configuración de permisos"""
    permisos_info = {
        'encriptado': False,
        'puede_editar': False,
        'puede_imprimir': False,
        'puede_copiar': False,
        'restricciones': []
    }
    
    if hasattr(reader, 'security') and reader.security:
        permisos_info['encriptado'] = True
        p_value = abs(reader.security.p)
        
        for bit, descripcion in PERMISSIONS_FLAGS.items():
            if (p_value >> (bit - 1)) & 1:
                permisos_info['restricciones'].append(descripcion)
        
        permisos_info['puede_imprimir'] = any("imprimir" in d.lower() for d in permisos_info['restricciones'])
        permisos_info['puede_copiar'] = any("copiar" in d.lower() for d in permisos_info['restricciones'])
        permisos_info['puede_editar'] = any("modificar" in d.lower() for d in permisos_info['restricciones'])

    return permisos_info


def contar_imagenes(reader: PdfReader) -> int:
    """Cuenta imágenes embebidas en el PDF"""
    contador = 0
    try:
        for page in reader.pages:
            if "/Resources" in page and "/XObject" in page["/Resources"]:
                xobjects = page["/Resources"]["/XObject"]
                if isinstance(xobjects, IndirectObject):
                    xobjects = xobjects.get_object()
                
                for obj_name in xobjects:
                    obj = xobjects[obj_name]
                    if isinstance(obj, IndirectObject):
                        obj = obj.get_object()
                    
                    if "/Subtype" in obj and obj["/Subtype"] == "/Image":
                        contador += 1
    except Exception as e:
        logger.debug(f"Error contando imágenes: {e}")
    
    return contador


def extraer_info_pdf(ruta_pdf: str, extraer_archivos: bool = False) -> Dict:
    """Extrae información completa del PDF con análisis de seguridad y Canary Tokens"""
    
    hash_data = calcular_hash_y_tamano(ruta_pdf)
    
    info = {
        'version_script': VERSION,
        'fecha_analisis': datetime.now().isoformat(),
        'ruta': ruta_pdf,
        'sha256': hash_data['sha256'],
        'md5': hash_data['md5'],
        'tamano_bytes': hash_data['tamano_bytes'],
        'estado_seguridad': 'OK - Sin Contraseña',
        'conteo_paginas': 0,
        'conteo_imagenes': 0,
        'compresion_detectada': 'Sí (Usa streams)',
        'restricciones_uso': {},
        'metadatos_tiempo_creacion': {},
        'campos_formulario': {},
        'tiene_javascript': False,
        'js_completo': [],
        'texto_completo': '',
        'urls_encontradas': [],
        'urls_analizadas': [],
        'archivos_embebidos': [],
        'acciones_automaticas': {},
        'puntuacion_riesgo': 0,
        'nivel_riesgo': '✅ MÍNIMO',
        'razones_riesgo': []
    }

    try:
        if not os.access(ruta_pdf, os.R_OK):
            info['error'] = "Error: Sin permisos de lectura para este archivo."
            return info
        
        # Leer contenido completo para análisis de URLs
        with open(ruta_pdf, 'rb') as f:
            pdf_content = f.read()
            
        with open(ruta_pdf, 'rb') as f:
            reader = PdfReader(f)
            
            # Manejar encriptación
            info['restricciones_uso'] = obtener_permisos(reader)
            
            if reader.is_encrypted:
                info['estado_seguridad'] = '❌ ENCRIPTADO - Requiere Contraseña'
                if not intentar_desencriptar(reader):
                    return info
            
            # Información básica
            info['conteo_paginas'] = len(reader.pages)
            info['conteo_imagenes'] = contar_imagenes(reader)
            
            # Metadatos
            metadatos = {k.replace('/', ''): v for k, v in reader.metadata.items()} if reader.metadata else {}
            
            open_action_str = 'Ninguna/N/A'
            try:
                root = reader.trailer.get("/Root")
                if root and "/OpenAction" in root:
                    open_action_str = str(root["/OpenAction"])[:100]
            except:
                pass
            
            info['metadatos_tiempo_creacion'] = {
                'Titulo': metadatos.get('Title', 'N/A'),
                'Autor': metadatos.get('Author', 'N/A'),
                'Creador': metadatos.get('Creator', 'N/A'),
                'Productor': metadatos.get('Producer', 'N/A'),
                'FechaCreacion': metadatos.get('CreationDate', 'N/A'),
                'FechaModificacion': metadatos.get('ModDate', 'N/A'),
                'OpenAction': open_action_str
            }

            # Campos de formulario
            try:
                fields = reader.get_fields()
                if fields:
                    info['campos_formulario'] = {
                        name: {
                            'Tipo': str(field.get('/FT', 'Desconocido')).replace('/', ''),
                            'Valor': str(field.get('/V', 'Vacío'))
                        }
                        for name, field in fields.items()
                    }
            except:
                pass

            # JavaScript
            js_completo = buscar_javascript(reader)
            if js_completo:
                info['tiene_javascript'] = True
                info['js_completo'] = js_completo 

            # Acciones automáticas y objetos sospechosos
            info['acciones_automaticas'] = analizar_acciones_automaticas(reader)

            # Extracción y análisis de URLs con detección de Canary Tokens
            info['urls_encontradas'] = ExtraerURLs.extraer_del_pdf(reader, pdf_content)
            
            # Analizar cada URL encontrada
            for url in info['urls_encontradas']:
                url_analizada = URLAnalyzer.analizar_url(url)
                info['urls_analizadas'].append(url_analizada)

            # Archivos embebidos
            info['archivos_embebidos'] = ArchivosEmbebidos.extraer_info(reader)
            
            if extraer_archivos and info['archivos_embebidos']:
                ArchivosEmbebidos.guardar_embebidos(reader, ruta_pdf)

            # Extracción de texto
            try:
                text_pages = [page.extract_text() for page in reader.pages]
                info['texto_completo'] = "\n".join(text_pages)
                guardar_texto_en_txt(ruta_pdf, info['texto_completo'])
            except Exception as e:
                logger.warning(f"Error extrayendo texto: {e}")

            # Calcular riesgo (incluye detección de Canary Tokens)
            puntuacion, nivel, razones = RiesgoCalculador.calcular_puntuacion(info)
            info['puntuacion_riesgo'] = puntuacion
            info['nivel_riesgo'] = nivel
            info['razones_riesgo'] = razones

    except Exception as e:
        info['error'] = f"Error de procesamiento: {type(e).__name__}: {e}"
        logger.error(f"Error procesando {ruta_pdf}: {e}")

    return info

# --- FUNCIONES DE PRESENTACIÓN ---

def imprimir_resultado(datos: Dict, modo_verboso: bool = True):
    """Imprime resultados en formato limpio"""
    print("\n" + "="*80)
    print(f"📄 Análisis Completo de PDF: {datos.get('ruta', 'N/A')}")
    print("="*80)

    if 'error' in datos:
        print(f"❌ ERROR: {datos['error']}")
        return
    
    # --- EVALUACIÓN DE RIESGO ---
    print(f"\n🎯 EVALUACIÓN DE RIESGO: {datos['nivel_riesgo']} (Puntuación: {datos['puntuacion_riesgo']}/100)")
    if datos['razones_riesgo']:
        print("   Indicadores:")
        for razon in datos['razones_riesgo']:
            print(f"   {razon}")
    
    restricciones = datos['restricciones_uso']
    
    # --- 1. IDENTIFICACIÓN ---
    print("\n--- 1. IDENTIFICACIÓN DE ARCHIVO ---")
    print(f"  • Tamaño: {datos['tamano_bytes']:,} bytes")
    print(f"  • SHA256: {datos['sha256']}")
    print(f"  • MD5: {datos['md5']}")
    print(f"  • Páginas: {datos['conteo_paginas']}")
    print(f"  • Imágenes embebidas: {datos['conteo_imagenes']}")
    
    # --- 2. METADATOS ---
    print("\n--- 2. METADATOS Y CRONOLOGÍA ---")
    m = datos['metadatos_tiempo_creacion']
    print(f"  • Título: {m['Titulo']}")
    print(f"  • Autor: {m['Autor']}")
    print(f"  • Creador: {m['Creador']}")
    print(f"  • Productor: {m['Productor']}")
    print(f"  • Fecha Creación: {m['FechaCreacion']}")
    print(f"  • Fecha Modificación: {m['FechaModificacion']}")
    print(f"  • OpenAction: {m['OpenAction']}")
    
    # --- 3. SEGURIDAD Y PERMISOS ---
    print("\n--- 3. SEGURIDAD Y PERMISOS ---")
    print(f"  • Estado: {datos['estado_seguridad']}")
    print(f"  • Compresión: {datos['compresion_detectada']}")
    
    if restricciones.get('encriptado'):
        print("\n  Permisos de Usuario:")
        print(f"    - Imprimir: {'✅' if restricciones.get('puede_imprimir') else '❌'}")
        print(f"    - Copiar/Extraer: {'✅' if restricciones.get('puede_copiar') else '❌'}")
        print(f"    - Editar/Modificar: {'✅' if restricciones.get('puede_editar') else '❌'}")
        
        if modo_verboso and restricciones.get('restricciones'):
            print("\n  Detalle de Permisos:")
            for p in restricciones['restricciones']:
                print(f"    • {p}")
    else:
        print("  • Sin encriptación. Todas las acciones permitidas.")

    # --- 4. ANÁLISIS DE SEGURIDAD ---
    print("\n--- 4. ANÁLISIS DE SEGURIDAD (OBJETOS SOSPECHOSOS) ---")
    acciones = datos['acciones_automaticas']
    
    tiene_sospechosos = any([
        acciones.get('tiene_openaction'),
        acciones.get('tiene_aa'),
        acciones.get('tiene_launch'),
        acciones.get('tiene_uri'),
        acciones.get('tiene_submitform')
    ])
    
    if tiene_sospechosos:
        print("  ⚠️  OBJETOS SOSPECHOSOS DETECTADOS:")
        if acciones.get('tiene_openaction'):
            print("    • /OpenAction: Ejecuta acciones al abrir el PDF")
        if acciones.get('tiene_aa'):
            print("    • /AA: Acciones adicionales automáticas")
        if acciones.get('tiene_launch'):
            print("    • /Launch: Intenta ejecutar programas externos ⚠️")
        if acciones.get('tiene_uri'):
            print("    • /URI: Contiene enlaces a URLs externas")
        if acciones.get('tiene_submitform'):
            print("    • /SubmitForm: Formulario que envía datos")
        if acciones.get('tiene_importdata'):
            print("    • /ImportData: Importa datos externos")
        
        if acciones.get('objetos_sospechosos'):
            print("\n  Detalles:")
            for obj in acciones['objetos_sospechosos']:
                print(f"    • {obj}")
    else:
        print("  ✅ No se detectaron objetos sospechosos")

    # --- 5. DETECCIÓN DE CANARY TOKENS Y TRACKING ---
    print("\n--- 5. ANÁLISIS DE URLs Y CANARY TOKENS ---")
    
    # Filtrar URLs ignoradas para el conteo
    urls_relevantes = [u for u in datos['urls_analizadas'] if u['riesgo'] != 'IGNORADO']
    
    if urls_relevantes:
        print(f"  🔗 {len(urls_relevantes)} URL(s) relevante(s) detectada(s)")
        
        # Canary Tokens - MÁXIMA PRIORIDAD
        canary_tokens = [u for u in urls_relevantes if u['es_canary_token']]
        if canary_tokens:
            print(f"\n  🚨 ¡CANARY TOKEN DETECTADO! ({len(canary_tokens)} token(s))")
            print("  ⚠️  ADVERTENCIA: Este PDF está siendo rastreado.")
            print("  ⚠️  El propietario recibirá una alerta cuando se abra.")
            for token in canary_tokens:
                print(f"\n    • URL: {token['url']}")
                print(f"      └─ Servicio: {token['servicio']} ({token['tipo']})")
                print(f"      └─ Riesgo: {token['riesgo']} (Puntuación: {token['puntuacion']})")
                if token.get('token_id'):
                    print(f"      └─ Token ID: {token['token_id']}")
                if modo_verboso and token['razones']:
                    for razon in token['razones']:
                        print(f"         • {razon}")
        
        # Servicios de tracking
        tracking = [u for u in urls_relevantes if u['es_tracking'] and not u['es_canary_token']]
        if tracking:
            print(f"\n  📡 SERVICIOS DE TRACKING: {len(tracking)}")
            for track in tracking:
                print(f"    • {track['url']}")
                print(f"      └─ Servicio: {track['servicio']} ({track['tipo']})")
                print(f"      └─ Riesgo: {track['riesgo']}")
        
        # Otras URLs con riesgo
        otras_urls = [u for u in urls_relevantes 
                     if not u['es_canary_token'] and not u['es_tracking'] and u['riesgo'] not in ['BAJO', 'IGNORADO']]
        if otras_urls and modo_verboso:
            print(f"\n  🌐 OTRAS URLs SOSPECHOSAS: {len(otras_urls)}")
            for url_info in otras_urls[:5]:
                print(f"    • {url_info['url']}")
                print(f"      └─ Riesgo: {url_info['riesgo']} (Puntuación: {url_info['puntuacion']})")
                if url_info['razones']:
                    print(f"      └─ {', '.join(url_info['razones'][:2])}")
        
        # Mostrar URLs ignoradas (metadatos) si modo verboso
        urls_ignoradas = [u for u in datos['urls_analizadas'] if u['riesgo'] == 'IGNORADO']
        if urls_ignoradas and modo_verboso:
            print(f"\n  ℹ️  URLs de Metadatos (Ignoradas): {len(urls_ignoradas)}")
            for url_info in urls_ignoradas[:3]:
                print(f"    • {url_info['url']}")
    else:
        print("  ✅ No se detectaron URLs externas relevantes")

    # --- 6. JAVASCRIPT ---
    print("\n--- 6. CÓDIGO JAVASCRIPT ---")
    if datos['tiene_javascript']:
        print(f"  ⚠️  JAVASCRIPT DETECTADO: {len(datos['js_completo'])} script(s)")
        if modo_verboso:
            for i, js in enumerate(datos['js_completo']):
                print(f"\n  *** SCRIPT {i+1} ***")
                print(js.strip()[:500] + "..." if len(js) > 500 else js.strip())
                print(f"  *** FIN SCRIPT {i+1} ***")
    else:
        print("  ✅ No se encontró JavaScript")

    # --- 7. ARCHIVOS EMBEBIDOS ---
    print("\n--- 7. ARCHIVOS EMBEBIDOS ---")
    if datos['archivos_embebidos']:
        print(f"  📎 {len(datos['archivos_embebidos'])} archivo(s) embebido(s):")
        for archi in datos['archivos_embebidos']:
            print(f"    • {archi['nombre']} ({archi['tamano']} bytes) - Tipo: {archi['tipo']}")
    else:
        print("  ✅ No hay archivos embebidos")

    # --- 8. CAMPOS DE FORMULARIO ---
    print("\n--- 8. CAMPOS DE FORMULARIO ---")
    campos = datos['campos_formulario']
    if campos:
        print(f"  📝 {len(campos)} campo(s) detectado(s):")
        for name, details in list(campos.items())[:10]:
            print(f"    • {name} | Tipo: {details['Tipo']} | Valor: {details['Valor']}")
        if len(campos) > 10:
            print(f"    ... y {len(campos) - 10} campos más")
    else:
        print("  • Sin campos de formulario")

    # --- 9. CONTENIDO DE TEXTO ---
    if modo_verboso:
        print("\n--- 9. CONTENIDO DE TEXTO (PREVIEW) ---")
        print("  • Texto exportado a archivo .txt")
        print("  " + "-"*76)
        texto_consola = datos['texto_completo']
        preview = texto_consola[:600] if len(texto_consola) > 600 else texto_consola
        print(preview)
        if len(texto_consola) > 600:
            print("\n  ... [contenido truncado]")
        print("  " + "-"*76)

    print("\n" + "="*80 + "\n")


def guardar_json(datos: Dict, ruta_salida: str = None):
    """Guarda resultados en JSON"""
    if ruta_salida is None:
        ruta_salida = os.path.splitext(datos['ruta'])[0] + "_analisis.json"
    
    datos_json = datos.copy()
    if len(datos_json.get('texto_completo', '')) > 10000:
        datos_json['texto_completo'] = datos_json['texto_completo'][:10000] + "... [truncado]"
    
    try:
        with open(ruta_salida, 'w', encoding='utf-8') as f:
            json.dump(datos_json, f, indent=2, ensure_ascii=False)
        logger.info(f"  > Reporte JSON guardado: {ruta_salida}")
    except Exception as e:
        logger.error(f"Error guardando JSON: {e}")


# --- PROCESAMIENTO ---

def procesar_ruta(ruta: str, extraer_archivos: bool = False, 
                  guardar_json_flag: bool = False, modo_verboso: bool = True):
    """Procesa un único archivo PDF"""
    logger.info(f"Iniciando análisis de: {ruta}")
    info = extraer_info_pdf(ruta, extraer_archivos)
    imprimir_resultado(info, modo_verboso)
    
    if guardar_json_flag:
        guardar_json(info)


def procesar_carpeta(ruta_carpeta: str, extraer_archivos: bool = False,
                     guardar_json_flag: bool = False, modo_verboso: bool = True,
                     paralelo: bool = False):
    """Procesa todos los PDFs en una carpeta"""
    logger.info(f"Iniciando análisis recursivo de: {ruta_carpeta}")
    
    pdfs = []
    for root, _, files in os.walk(ruta_carpeta):
        for file in files:
            if file.lower().endswith('.pdf'):
                pdfs.append(os.path.join(root, file))

    if not pdfs:
        logger.warning(f"No se encontraron archivos PDF en '{ruta_carpeta}'")
        return

    logger.info(f"Encontrados {len(pdfs)} archivo(s) PDF")

    resultados = []
    
    if paralelo and len(pdfs) > 1:
        logger.info("Procesamiento paralelo activado")
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(extraer_info_pdf, pdf, extraer_archivos): pdf 
                for pdf in pdfs
            }
            
            for future in as_completed(futures):
                pdf = futures[future]
                try:
                    resultado = future.result()
                    imprimir_resultado(resultado, modo_verboso)
                    if guardar_json_flag:
                        guardar_json(resultado)
                    resultados.append(resultado)
                except Exception as e:
                    logger.error(f"Error procesando {pdf}: {e}")
    else:
        for pdf in pdfs:
            try:
                procesar_ruta(pdf, extraer_archivos, guardar_json_flag, modo_verboso)
                resultados.append({'ruta': pdf})
            except Exception as e:
                logger.error(f"Error procesando {pdf}: {e}")
    
    # Resumen global
    print("\n" + "="*80)
    print("📊 RESUMEN GLOBAL")
    print("="*80)
    print(f"Total archivos analizados: {len(resultados)}")
    
    pdfs_con_canary = 0
    for r in resultados:
        if r.get('urls_analizadas'):
            if any(u['es_canary_token'] for u in r['urls_analizadas']):
                pdfs_con_canary += 1
    
    if pdfs_con_canary > 0:
        print(f"🚨 PDFs con CANARY TOKENS: {pdfs_con_canary}")
    
    print("="*80 + "\n")


def main():
    print(f"""
╔═══════════════════════════════════════════╗
║  📄 PDF Analyzer Pro v{VERSION} - Simple scan ║
║  Análisis  en Documentos PDF              ║
╚═══════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(
        description=f"PDF Analyzer Pro v{VERSION} - Análisis completo con detección de Canary Tokens",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -a documento.pdf
  %(prog)s -a documento.pdf --json --extraer-embebidos
  %(prog)s -f ./carpeta_pdfs --paralelo
  %(prog)s -f ./carpeta_pdfs --json --quiet
  
Detección incluida:
  • Canary Tokens (canarytokens.com/org/net)
  • OpenAction y acciones automáticas
  • JavaScript malicioso
  • Archivos embebidos
  • Servicios de tracking
  • URLs sospechosas
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-a', '--archivo', 
        type=str, 
        help="Ruta a un único archivo PDF para analizar"
    )
    group.add_argument(
        '-f', '--carpeta', 
        type=str, 
        help="Ruta a una carpeta. Analiza recursivamente todos los PDFs"
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help="Guarda resultados en formato JSON"
    )
    
    parser.add_argument(
        '--extraer-embebidos',
        action='store_true',
        help="Extrae archivos embebidos a disco"
    )
    
    parser.add_argument(
        '--paralelo',
        action='store_true',
        help="Procesamiento paralelo para carpetas (más rápido)"
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help="Modo silencioso (menos detalles)"
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )

    args = parser.parse_args()

    # Validaciones
    if args.archivo and not os.path.exists(args.archivo):
        logger.error(f"El archivo no existe: {args.archivo}")
        sys.exit(1)
    
    if args.carpeta and not os.path.isdir(args.carpeta):
        logger.error(f"La ruta no es una carpeta válida: {args.carpeta}")
        sys.exit(1)

    modo_verboso = not args.quiet

    # Procesamiento
    if args.archivo:
        procesar_ruta(args.archivo, args.extraer_embebidos, args.json, modo_verboso)
    elif args.carpeta:
        procesar_carpeta(args.carpeta, args.extraer_embebidos, args.json, 
                        modo_verboso, args.paralelo)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operación cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        sys.exit(1)
