#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extractor de Contenido Base64 - Versión 2.4
Forense · Deduplicación SHA256 · Decodificación Robusta
Autor: Apuromafo
Fecha: 2025-10-06
"""

import sys
import re
import base64
import os
import json
import zipfile
import io
import hashlib
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURACIÓN GENERAL
# ============================================================================

CONFIG = {
    # Carpetas y organización
    'base_folder': 'Extracted',
    'timestamp_format': '%Y-%m-%d_%H-%M-%S',
    'organize_by_type': True,
    
    # Decodificación y extracción
    'min_base64_length': 136,  # Caracteres mínimos de Base64 (≈100 bytes)
    'min_decoded_size': 100,   # Bytes mínimos del archivo decodificado
    
    # Hash y deduplicación
    'hash_algorithm': 'SHA256',
    'enable_deduplication': True,
    'include_hash_in_filename': True,
    
    # Logs y reportes
    'generate_json_log': True,
    'generate_summary': True,
    'generate_duplicates_log': True,
    
    # Mapeo de tipos de archivo a carpetas
    'type_folders': {
        'Image': 'Images',
        'Document': 'Documents',
        'Office Document (Word)': 'Documents/Word',
        'Office Document (Word 97-2003)': 'Documents/Word',
        'Office Spreadsheet (Excel)': 'Documents/Excel',
        'Office Spreadsheet (Excel 97-2003)': 'Documents/Excel',
        'Office Presentation (PowerPoint)': 'Documents/PowerPoint',
        'Office Presentation (PowerPoint 97-2003)': 'Documents/PowerPoint',
        'Office Legacy Document': 'Documents/Office_Legacy',
        'Outlook Message': 'Documents/Outlook',
        'Archive': 'Archives',
        'Archive (ZIP)': 'Archives',
        'Audio': 'Audio',
        'Video': 'Video',
        'Executable': 'Executables',
        'Binary Data': 'Others',
        'RIFF Container': 'Others'
    }
}

# ============================================================================
# DEFINICIÓN DE FIRMAS MÁGICAS (MAGIC BYTES)
# ============================================================================
# Formato: bytes_inicio: {extensión, tipo_archivo}
# Para agregar nuevos tipos, añade una nueva entrada aquí

MAGIC_BYTES_DEFINITIONS = [
    # Imágenes
    {
        'signature': b'\xff\xd8\xff',
        'extension': 'jpg',
        'type': 'Image',
        'description': 'JPEG Image'
    },
    {
        'signature': b'\x89PNG\r\n\x1a\n',
        'extension': 'png',
        'type': 'Image',
        'description': 'PNG Image'
    },
    {
        'signature': b'GIF89a',
        'extension': 'gif',
        'type': 'Image',
        'description': 'GIF Image (89a)'
    },
    {
        'signature': b'GIF87a',
        'extension': 'gif',
        'type': 'Image',
        'description': 'GIF Image (87a)'
    },
    {
        'signature': b'BM',
        'extension': 'bmp',
        'type': 'Image',
        'description': 'Bitmap Image'
    },
    {
        'signature': b'II*\x00',
        'extension': 'tif',
        'type': 'Image',
        'description': 'TIFF Image (little-endian)'
    },
    {
        'signature': b'MM\x00*',
        'extension': 'tif',
        'type': 'Image',
        'description': 'TIFF Image (big-endian)'
    },
    
    # Documentos
    {
        'signature': b'%PDF-',
        'extension': 'pdf',
        'type': 'Document',
        'description': 'PDF Document'
    },
    
    # Office Antiguos (OLE2/Compound Binary)
    {
        'signature': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
        'extension': 'ole',
        'type': 'Office Legacy Document',
        'description': 'Microsoft Office Legacy (97-2003) or OLE2 Document'
    },
    
    # Archivos comprimidos
    {
        'signature': b'PK\x03\x04',
        'extension': 'zip',
        'type': 'Archive',
        'description': 'ZIP Archive or Office Modern (DOCX/XLSX/PPTX)'
    },
    {
        'signature': b'PK\x05\x06',
        'extension': 'zip',
        'type': 'Archive',
        'description': 'ZIP Archive (empty)'
    },
    {
        'signature': b'PK\x07\x08',
        'extension': 'zip',
        'type': 'Archive',
        'description': 'ZIP Archive (spanned)'
    },
    {
        'signature': b'Rar!\x1a\x07\x00',
        'extension': 'rar',
        'type': 'Archive',
        'description': 'RAR Archive (v1.5+)'
    },
    {
        'signature': b'Rar!\x1a\x07\x01\x00',
        'extension': 'rar',
        'type': 'Archive',
        'description': 'RAR Archive (v5.0+)'
    },
    {
        'signature': b'7z\xBC\xAF\x27\x1C',
        'extension': '7z',
        'type': 'Archive',
        'description': '7-Zip Archive'
    },
    {
        'signature': b'\x1f\x8b',
        'extension': 'gz',
        'type': 'Archive',
        'description': 'GZIP Archive'
    },
    {
        'signature': b'BZh',
        'extension': 'bz2',
        'type': 'Archive',
        'description': 'BZIP2 Archive'
    },
    {
        'signature': b'\xfd7zXZ\x00',
        'extension': 'xz',
        'type': 'Archive',
        'description': 'XZ Archive'
    },
    
    # Audio
    {
        'signature': b'RIFF',
        'extension': 'wav',
        'type': 'Audio',
        'description': 'RIFF Container (WAV/AVI/WebP)'
    },
    {
        'signature': b'ID3',
        'extension': 'mp3',
        'type': 'Audio',
        'description': 'MP3 Audio (ID3)'
    },
    {
        'signature': b'\xff\xfb',
        'extension': 'mp3',
        'type': 'Audio',
        'description': 'MP3 Audio (MPEG-1 Layer 3)'
    },
    {
        'signature': b'\xff\xf3',
        'extension': 'mp3',
        'type': 'Audio',
        'description': 'MP3 Audio (MPEG-1 Layer 3)'
    },
    {
        'signature': b'\xff\xf2',
        'extension': 'mp3',
        'type': 'Audio',
        'description': 'MP3 Audio (MPEG-2 Layer 3)'
    },
    {
        'signature': b'OggS',
        'extension': 'ogg',
        'type': 'Audio',
        'description': 'OGG Audio'
    },
    {
        'signature': b'fLaC',
        'extension': 'flac',
        'type': 'Audio',
        'description': 'FLAC Audio'
    },
    
    # Video
    {
        'signature': b'\x00\x00\x00\x18ftypmp42',
        'extension': 'mp4',
        'type': 'Video',
        'description': 'MP4 Video'
    },
    {
        'signature': b'\x00\x00\x00\x1cftypisom',
        'extension': 'mp4',
        'type': 'Video',
        'description': 'MP4 Video (isom)'
    },
    
    # Ejecutables
    {
        'signature': b'MZ',
        'extension': 'exe',
        'type': 'Executable',
        'description': 'Windows Executable (PE)'
    },
    {
        'signature': b'\x7fELF',
        'extension': 'elf',
        'type': 'Executable',
        'description': 'Linux Executable (ELF)'
    },
]

# Construir diccionario de búsqueda rápida desde las definiciones
MAGIC_BYTES = {item['signature']: {'ext': item['extension'], 'type': item['type']} 
               for item in MAGIC_BYTES_DEFINITIONS}

# ============================================================================
# STRINGS Y MENSAJES DEL PROGRAMA
# ============================================================================

STRINGS = {
    # Banner y títulos
    'banner_title': 'Extractor de Contenido Base64 - Versión 2.4',
    'banner_subtitle': 'Forense · Deduplicación SHA256 · Decodificación Robusta',
    
    # Mensajes de ayuda
    'usage': 'Uso: python3 extrae.py <archivo_o_carpeta>',
    'examples_title': 'Ejemplos:',
    'example_file': '  python3 extrae.py documento.txt',
    'example_dir': '  python3 extrae.py ./POC/',
    'example_win': '  python3 extrae.py C:\\Malware_Samples\\',
    
    'features_title': 'Características:',
    'feature_1': '  ✓ Decodificación robusta (Base64 estándar + URL-safe)',
    'feature_2': '  ✓ Corrección automática de padding',
    'feature_3': '  ✓ Deduplicación por hash SHA256 completo',
    'feature_4': '  ✓ Nombres de archivo = hash completo (64 caracteres)',
    'feature_5': '  ✓ Procesamiento recursivo de directorios',
    'feature_6': '  ✓ Organización automática por tipo de archivo',
    
    # Mensajes de proceso
    'analyzing': '🔎 Analizando',
    'processing': 'Procesando',
    'input_file': '📄 Entrada: Archivo individual',
    'input_dir': '📁 Entrada: Directorio',
    'path': '   Ruta',
    'extraction_folder': '📁 Carpeta de extracción',
    'deduplication': '🔒 Deduplicación: Activada (SHA256)',
    'decoding_mode': '🔧 Decodificación: Robusta (Standard + URL-safe + Padding flexible)',
    'mode': '🔍 Modo',
    'files_found': '📊 Archivos encontrados',
    'files_to_process': '📂 Archivos a procesar',
    
    # Preguntas al usuario
    'ask_recursive': '¿Desea procesar subdirectorios de forma recursiva?',
    'ask_process': '¿Procesar {count} archivo(s)?',
    'invalid_response': '⚠️  Respuesta inválida. Por favor, ingrese \'s\' (sí) o \'n\' (no).',
    'cancelled': '⚠️  Operación cancelada por el usuario.',
    
    # Resultados
    'extracted': '✅ Únicos',
    'duplicates': '⏭️  Duplicados',
    'no_content': '⚠️  Sin contenido Base64 extraíble',
    'completed': '✅ Procesamiento completado',
    'files_processed': '   • Archivos procesados',
    'unique_extracted': '   • Archivos únicos extraídos',
    'duplicates_skipped': '   • Duplicados omitidos',
    'total_analyzed': '   • Total analizado',
    
    # Logs
    'log_json': '📄 Log JSON',
    'log_summary': '📝 Resumen',
    'log_duplicates': '📋 Duplicados',
    'no_logs': '⚠️  No se generaron logs (no se extrajo ningún archivo)',
    
    # Errores
    'error_not_found': '❌ Error: La ruta no existe',
    'error_no_files': '⚠️  No se encontraron archivos para procesar en el directorio.',
    'error_reading': '⚠️  Error al leer',
    'error_creating_folder': '❌ Error al crear carpeta',
    'error_saving': 'Error al guardar',
    'error_log': '❌ Error al generar log',
    
    # Archivos de salida
    'log_filename': 'extraction_log.json',
    'summary_filename': 'RESUMEN.txt',
    'duplicates_filename': 'DUPLICADOS.txt',
    
    # Títulos de reportes
    'report_summary_title': 'RESUMEN DE EXTRACCIÓN DE ARCHIVOS BASE64',
    'report_duplicates_title': 'REGISTRO DE ARCHIVOS DUPLICADOS (OMITIDOS)',
    'report_statistics': 'ESTADÍSTICAS',
    'report_detail': 'DETALLE DE ARCHIVOS ÚNICOS',
    'report_dup_detail': 'DETALLE',
}

# ============================================================================
# REGEX PATTERNS
# ============================================================================

PATTERNS = {
    # Regex permisivo para Base64: captura caracteres válidos (estándar + URL-safe + padding)
    # Mínimo definido por CONFIG['min_base64_length']
    'base64': r'[A-Za-z0-9+/=\-_]{' + str(CONFIG['min_base64_length']) + r',}'
}

# ============================================================================
# UTILIDADES DE HASH
# ============================================================================

def calculate_sha256(data):
    """
    Calcula el hash SHA256 de datos binarios.
    
    Args:
        data: Bytes a hashear
    
    Returns:
        String hexadecimal del hash SHA256 completo (64 caracteres)
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(data)
    return hash_obj.hexdigest()

# ============================================================================
# DECODIFICACIÓN ROBUSTA DE BASE64
# ============================================================================

def decode_base64_robust(base64_string):
    """
    Decodifica Base64 de forma robusta, manejando:
    - Padding faltante o incorrecto
    - Base64 estándar (+ y /)
    - Base64 URL-safe (- y _)
    
    Args:
        base64_string: String Base64 a decodificar
    
    Returns:
        Bytes decodificados si tiene éxito, None si falla
    """
    base64_string = base64_string.strip()
    base64_string_clean = base64_string.rstrip('=')
    
    missing_padding = len(base64_string_clean) % 4
    if missing_padding:
        base64_string_clean += '=' * (4 - missing_padding)
    
    try:
        decoded_data = base64.b64decode(base64_string_clean, validate=True)
        return decoded_data
    except (base64.binascii.Error, ValueError):
        pass
    
    try:
        decoded_data = base64.urlsafe_b64decode(base64_string_clean)
        return decoded_data
    except (base64.binascii.Error, ValueError):
        pass
    
    return None

# ============================================================================
# UTILIDADES DE USUARIO
# ============================================================================

def ask_yes_no(question, default='y'):
    """Pregunta al usuario una respuesta Sí/No."""
    valid_yes = ['s', 'si', 'sí', 'y', 'yes', 'sim']
    valid_no = ['n', 'no', 'nao', 'não']
    
    prompt = f"{question} [S/n]: " if default.lower() == 'y' else f"{question} [s/N]: "
    
    while True:
        try:
            response = input(prompt).strip().lower()
            
            if not response:
                return default.lower() == 'y'
            
            if response in valid_yes:
                return True
            elif response in valid_no:
                return False
            else:
                print(STRINGS['invalid_response'])
        except KeyboardInterrupt:
            print(f"\n\n{STRINGS['cancelled']}")
            sys.exit(0)

def get_files_to_process(path_input, recursive=False):
    """Obtiene lista de archivos a procesar."""
    files_to_process = []
    
    if os.path.isfile(path_input):
        files_to_process.append(path_input)
    elif os.path.isdir(path_input):
        if recursive:
            for root, dirs, files in os.walk(path_input):
                for filename in files:
                    files_to_process.append(os.path.join(root, filename))
        else:
            for item in os.listdir(path_input):
                file_path = os.path.join(path_input, item)
                if os.path.isfile(file_path):
                    files_to_process.append(file_path)
    
    return files_to_process

# ============================================================================
# GESTIÓN DE CARPETAS
# ============================================================================

class FolderManager:
    """Gestiona la estructura de carpetas."""
    
    def __init__(self, base_folder, timestamp_format, organize_by_type):
        self.base_folder = base_folder
        self.timestamp_format = timestamp_format
        self.organize_by_type = organize_by_type
        
        timestamp = datetime.now().strftime(self.timestamp_format)
        self.extraction_folder = os.path.join(self.base_folder, timestamp)
        self._create_folder(self.extraction_folder)
    
    def _create_folder(self, folder_path):
        """Crea carpeta si no existe."""
        try:
            os.makedirs(folder_path, exist_ok=True)
        except Exception as e:
            print(f"{STRINGS['error_creating_folder']} {folder_path}: {e}")
            raise
    
    def get_file_path(self, file_type, filename):
        """Retorna la ruta completa donde debe guardarse el archivo."""
        if self.organize_by_type and file_type in CONFIG['type_folders']:
            subfolder = CONFIG['type_folders'][file_type]
            target_folder = os.path.join(self.extraction_folder, subfolder)
            self._create_folder(target_folder)
        else:
            target_folder = self.extraction_folder
        
        return os.path.join(target_folder, filename)
    
    def get_log_path(self):
        return os.path.join(self.extraction_folder, STRINGS['log_filename'])
    
    def get_summary_path(self):
        return os.path.join(self.extraction_folder, STRINGS['summary_filename'])
    
    def get_duplicates_path(self):
        return os.path.join(self.extraction_folder, STRINGS['duplicates_filename'])

# ============================================================================
# FUNCIONES DE DETECCIÓN DE TIPOS DE ARCHIVO
# ============================================================================

def detect_office_modern(data):
    """Detecta documentos Office modernos (DOCX/XLSX/PPTX)."""
    if not data.startswith(b'PK\x03\x04'):
        return None
    
    try:
        zip_buffer = io.BytesIO(data)
        with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
            file_list = zip_file.namelist()
            
            if any('word/document.xml' in f or f.startswith('word/') for f in file_list):
                return {'ext': 'docx', 'type': 'Office Document (Word)'}
            
            if any('xl/workbook.xml' in f or f.startswith('xl/') for f in file_list):
                return {'ext': 'xlsx', 'type': 'Office Spreadsheet (Excel)'}
            
            if any('ppt/presentation.xml' in f or f.startswith('ppt/') for f in file_list):
                return {'ext': 'pptx', 'type': 'Office Presentation (PowerPoint)'}
            
            if '[Content_Types].xml' in file_list:
                return {'ext': 'office', 'type': 'Office Document (Unknown)'}
    except (zipfile.BadZipFile, Exception):
        pass
    
    return None

def detect_office_legacy(data):
    """Detecta documentos Office antiguos (OLE2)."""
    if not data.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
        return {'ext': 'ole', 'type': 'Office Legacy Document'}
    
    if b'Word.Document' in data[:2048] or b'Microsoft Word' in data[:2048]:
        return {'ext': 'doc', 'type': 'Office Document (Word 97-2003)'}
    
    if b'Workbook' in data[:2048] or b'Microsoft Excel' in data[:2048]:
        return {'ext': 'xls', 'type': 'Office Spreadsheet (Excel 97-2003)'}
    
    if b'PowerPoint' in data[:2048] or b'Current User' in data[:2048]:
        return {'ext': 'ppt', 'type': 'Office Presentation (PowerPoint 97-2003)'}
    
    if b'__substg1.0_' in data[:2048]:
        return {'ext': 'msg', 'type': 'Outlook Message'}
    
    return {'ext': 'ole', 'type': 'Office Legacy Document'}

def detect_riff_subtype(data):
    """Detecta subtipos RIFF (WAV/AVI/WebP)."""
    if data.startswith(b'RIFF') and len(data) >= 12:
        riff_type = data[8:12]
        
        if riff_type == b'WAVE':
            return {'ext': 'wav', 'type': 'Audio'}
        elif riff_type == b'AVI ':
            return {'ext': 'avi', 'type': 'Video'}
        elif riff_type == b'WEBP':
            return {'ext': 'webp', 'type': 'Image'}
    
    return {'ext': 'riff', 'type': 'RIFF Container'}

# ============================================================================
# IDENTIFICACIÓN Y GUARDADO
# ============================================================================

def identify_and_save(data, folder_manager, file_hash):
    """Identifica tipo de archivo y lo guarda con hash SHA256 completo."""
    
    file_info = {'ext': 'bin', 'type': 'Binary Data'}

    for magic, info in MAGIC_BYTES.items():
        if data.startswith(magic):
            file_info = info.copy()
            
            if magic == b'PK\x03\x04':
                office_info = detect_office_modern(data)
                file_info = office_info if office_info else {'ext': 'zip', 'type': 'Archive (ZIP)'}
            elif magic == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                file_info = detect_office_legacy(data)
            elif magic == b'RIFF':
                file_info = detect_riff_subtype(data)
            
            break
    
    filename = f"{file_hash}.{file_info['ext']}"
    full_path = folder_manager.get_file_path(file_info['type'], filename)
    
    try:
        with open(full_path, 'wb') as f:
            f.write(data)
    except Exception as e:
        raise Exception(f"{STRINGS['error_saving']}: {e}")
    
    relative_path = os.path.relpath(full_path, folder_manager.extraction_folder)
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'file_path': relative_path,
        'file_name': filename,
        'sha256_hash': file_hash,
        'size_bytes': len(data),
        'detected_extension': file_info['ext'],
        'detected_type': file_info['type'],
        'status': 'SUCCESS'
    }
    
    return relative_path, log_entry

# ============================================================================
# PROCESAMIENTO DE ARCHIVOS
# ============================================================================

def process_single_file(file_path, folder_manager, hash_registry):
    """Procesa un archivo con decodificación robusta y deduplicación."""
    
    log_entries = []
    duplicates_log = []
    processed_b64_hashes = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"  {STRINGS['error_reading']} {file_path}: {e}")
        return log_entries, 0, []
    
    matches = re.finditer(PATTERNS['base64'], content, re.MULTILINE)
    extracted_count = 0
    
    for match in matches:
        base64_string = "".join(match.group(0).split())
        base64_string_normalized = base64_string.rstrip('=')
        
        if len(base64_string_normalized) < CONFIG['min_base64_length']:
            continue
        
        b64_hash = hash(base64_string_normalized)
        if b64_hash in processed_b64_hashes:
            continue
        processed_b64_hashes.add(b64_hash)
        
        decoded_data = decode_base64_robust(base64_string)
        
        if decoded_data is None or len(decoded_data) < CONFIG['min_decoded_size']:
            continue
        
        file_hash = calculate_sha256(decoded_data)
        
        if file_hash in hash_registry:
            duplicate_info = {
                'timestamp': datetime.now().isoformat(),
                'source_file': file_path,
                'sha256_hash': file_hash,
                'size_bytes': len(decoded_data),
                'original_file': hash_registry[file_hash]['file_path'],
                'original_source': hash_registry[file_hash]['source_file'],
                'status': 'DUPLICATE_SKIPPED'
            }
            duplicates_log.append(duplicate_info)
            continue
        
        try:
            relative_path, log_entry = identify_and_save(decoded_data, folder_manager, file_hash)
            log_entry['source_file'] = file_path
            log_entries.append(log_entry)
            
            hash_registry[file_hash] = {
                'file_path': relative_path,
                'source_file': file_path,
                'file_name': log_entry['file_name']
            }
            
            extracted_count += 1
        except Exception as e:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'source_file': file_path,
                'sha256_hash': file_hash,
                'error': str(e),
                'status': 'FAILURE'
            }
            log_entries.append(log_entry)
    
    return log_entries, extracted_count, duplicates_log

# ============================================================================
# EXTRACCIÓN PRINCIPAL
# ============================================================================

def extract_from_multiple_files(files_list, folder_manager):
    """Procesa múltiples archivos con deduplicación."""
    
    all_logs = []
    all_duplicates = []
    total_files_processed = 0
    total_extracted = 0
    hash_registry = {}
    
    print("=" * 70)
    print(f"{STRINGS['files_to_process']}: {len(files_list)}")
    print("=" * 70)
    print()
    
    for idx, file_path in enumerate(files_list, 1):
        file_name = os.path.basename(file_path)
        print(f"[{idx}/{len(files_list)}] {STRINGS['processing']}: {file_name}")
        
        logs, extracted, duplicates = process_single_file(file_path, folder_manager, hash_registry)
        
        all_logs.extend(logs)
        all_duplicates.extend(duplicates)
        total_extracted += extracted
        total_files_processed += 1
        
        if extracted > 0 or len(duplicates) > 0:
            print(f"  {STRINGS['extracted']}: {extracted} | {STRINGS['duplicates']}: {len(duplicates)}")
        else:
            print(f"  {STRINGS['no_content']}")
        print()
    
    print("=" * 70)
    print(STRINGS['completed'])
    print(f"{STRINGS['files_processed']}: {total_files_processed}")
    print(f"{STRINGS['unique_extracted']}: {total_extracted}")
    print(f"{STRINGS['duplicates_skipped']}: {len(all_duplicates)}")
    print(f"{STRINGS['total_analyzed']}: {total_extracted + len(all_duplicates)}")
    print("=" * 70)
    
    return all_logs, total_extracted, all_duplicates

# ============================================================================
# GENERACIÓN DE LOGS
# ============================================================================

def generate_audit_log(data, total_files, folder_manager, source_info, duplicates_count):
    """Genera log JSON."""
    
    successful = [e for e in data if e.get('status') == 'SUCCESS']
    failed = [e for e in data if e.get('status') == 'FAILURE']
    
    types_count = {}
    for entry in successful:
        file_type = entry.get('detected_type', 'Unknown')
        types_count[file_type] = types_count.get(file_type, 0) + 1
    
    audit_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'script_version': '2.4',
            'extraction_folder': folder_manager.extraction_folder,
            'organized_by_type': CONFIG['organize_by_type'],
            'deduplication_enabled': CONFIG['enable_deduplication'],
            'hash_algorithm': CONFIG['hash_algorithm'],
            'base64_decoding': 'Robust (Standard + URL-safe + Flexible Padding)',
            'source_info': source_info
        },
        'summary': {
            'total_files_extracted': total_files,
            'successful_extractions': len(successful),
            'failed_extractions': len(failed),
            'duplicates_skipped': duplicates_count,
            'total_analyzed': total_files + duplicates_count,
            'files_by_type': types_count
        },
        'extractions': data
    }
    
    log_path = folder_manager.get_log_path()
    
    try:
        with open(log_path, 'w', encoding='utf-8') as f:
            json.dump(audit_data, f, indent=4, ensure_ascii=False)
        print(f"\n{STRINGS['log_json']}: {os.path.basename(log_path)}")
    except Exception as e:
        print(f"\n{STRINGS['error_log']}: {e}")

def generate_duplicates_log(duplicates, folder_manager):
    """Genera archivo de log de duplicados."""
    
    if not duplicates:
        return
    
    duplicates_path = folder_manager.get_duplicates_path()
    
    try:
        with open(duplicates_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write(f"  {STRINGS['report_duplicates_title']}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Total de duplicados omitidos: {len(duplicates)}\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("-" * 70 + "\n")
            f.write(f"{STRINGS['report_dup_detail']}\n")
            f.write("-" * 70 + "\n\n")
            
            for idx, dup in enumerate(duplicates, 1):
                f.write(f"[{idx}] Duplicado encontrado\n")
                f.write(f"    Hash SHA256: {dup['sha256_hash']}\n")
                f.write(f"    Tamaño: {dup['size_bytes']:,} bytes\n")
                f.write(f"    Encontrado en: {dup['source_file']}\n")
                f.write(f"    Original guardado como: {dup['original_file']}\n")
                f.write(f"    Fuente original: {dup['original_source']}\n")
                f.write(f"    Timestamp: {dup['timestamp']}\n\n")
        
        print(f"{STRINGS['log_duplicates']}: {os.path.basename(duplicates_path)}")
    except Exception as e:
        print(f"{STRINGS['error_log']}: {e}")

def generate_summary(data, total_files, folder_manager, source_info, duplicates_count):
    """Genera resumen en texto."""
    
    summary_path = folder_manager.get_summary_path()
    successful = [e for e in data if e.get('status') == 'SUCCESS']
    
    types_count = {}
    for entry in successful:
        file_type = entry.get('detected_type', 'Unknown')
        types_count[file_type] = types_count.get(file_type, 0) + 1
    
    try:
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write(f"  {STRINGS['report_summary_title']}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Fecha y hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Fuente: {source_info['path']}\n")
            f.write(f"Tipo: {source_info['type']}\n")
            if source_info['type'] == 'Directorio':
                f.write(f"Modo recursivo: {'Sí' if source_info['recursive'] else 'No'}\n")
                f.write(f"Archivos procesados: {source_info['files_processed']}\n")
            f.write(f"Carpeta destino: {folder_manager.extraction_folder}\n")
            f.write(f"Organizado por tipo: {'Sí' if CONFIG['organize_by_type'] else 'No'}\n")
            f.write(f"Deduplicación: {'Activada' if CONFIG['enable_deduplication'] else 'Desactivada'} ({CONFIG['hash_algorithm']})\n")
            f.write(f"Decodificación: Robusta (Standard + URL-safe)\n\n")
            
            f.write("-" * 70 + "\n")
            f.write(f"{STRINGS['report_statistics']}\n")
            f.write("-" * 70 + "\n")
            f.write(f"Archivos únicos extraídos: {total_files}\n")
            f.write(f"Duplicados omitidos: {duplicates_count}\n")
            f.write(f"Total analizado: {total_files + duplicates_count}\n\n")
            
            if types_count:
                f.write("Archivos por tipo:\n")
                for file_type, count in sorted(types_count.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  • {file_type}: {count}\n")
            
            f.write("\n" + "-" * 70 + "\n")
            f.write(f"{STRINGS['report_detail']}\n")
            f.write("-" * 70 + "\n\n")
            
            for entry in successful:
                f.write(f"Archivo: {entry['file_name']}\n")
                f.write(f"  Ubicación: {entry['file_path']}\n")
                f.write(f"  Tipo: {entry['detected_type']}\n")
                f.write(f"  Tamaño: {entry['size_bytes']:,} bytes\n")
                f.write(f"  SHA256: {entry['sha256_hash']}\n")
                f.write(f"  Fuente: {entry.get('source_file', 'N/A')}\n\n")
        
        print(f"{STRINGS['log_summary']}: {os.path.basename(summary_path)}")
    except Exception as e:
        print(f"{STRINGS['error_log']}: {e}")

# ============================================================================
# PUNTO DE ENTRADA
# ============================================================================

def main():
    if len(sys.argv) != 2:
        print("╔" + "═" * 68 + "╗")
        print(f"║  {STRINGS['banner_title']: <66} ║")
        print(f"║  {STRINGS['banner_subtitle']: <66} ║")
        print("╚" + "═" * 68 + "╝")
        print()
        print(f"📋 {STRINGS['usage']}")
        print()
        print(STRINGS['examples_title'])
        print(STRINGS['example_file'])
        print(STRINGS['example_dir'])
        print(STRINGS['example_win'])
        print()
        print(STRINGS['features_title'])
        print(STRINGS['feature_1'])
        print(STRINGS['feature_2'])
        print(STRINGS['feature_3'])
        print(STRINGS['feature_4'])
        print(STRINGS['feature_5'])
        print(STRINGS['feature_6'])
        print()
        sys.exit(1)

    input_path = sys.argv[1]
    
    if not os.path.exists(input_path):
        print(f"{STRINGS['error_not_found']}: {input_path}")
        sys.exit(1)
    
    print("╔" + "═" * 68 + "╗")
    print(f"║  {STRINGS['banner_title']: <66} ║")
    print(f"║  {STRINGS['banner_subtitle']: <66} ║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    is_directory = os.path.isdir(input_path)
    is_file = os.path.isfile(input_path)
    
    recursive = False
    files_to_process = []
    
    if is_file:
        print(STRINGS['input_file'])
        print(f"{STRINGS['path']}: {input_path}")
        print()
        files_to_process = [input_path]
        source_info = {
            'path': input_path,
            'type': 'Archivo',
            'recursive': False,
            'files_processed': 1
        }
    
    elif is_directory:
        print(STRINGS['input_dir'])
        print(f"{STRINGS['path']}: {input_path}")
        print()
        
        recursive = ask_yes_no(STRINGS['ask_recursive'], default='n')
        print()
        
        files_to_process = get_files_to_process(input_path, recursive)
        
        if not files_to_process:
            print(STRINGS['error_no_files'])
            sys.exit(0)
        
        mode_text = "recursivo" if recursive else "no recursivo"
        print(f"{STRINGS['mode']}: {mode_text}")
        print(f"{STRINGS['files_found']}: {len(files_to_process)}")
        print()
        
        if not ask_yes_no(STRINGS['ask_process'].format(count=len(files_to_process)), default='y'):
            print(STRINGS['cancelled'])
            sys.exit(0)
        
        print()
        
        source_info = {
            'path': input_path,
            'type': 'Directorio',
            'recursive': recursive,
            'files_processed': len(files_to_process)
        }
    
    folder_manager = FolderManager(
        CONFIG['base_folder'],
        CONFIG['timestamp_format'],
        CONFIG['organize_by_type']
    )
    
    print(f"{STRINGS['extraction_folder']}: \033[1m{folder_manager.extraction_folder}\033[0m")
    print(STRINGS['deduplication'])
    print(STRINGS['decoding_mode'])
    print()
    
    all_logs, total_extracted, all_duplicates = extract_from_multiple_files(files_to_process, folder_manager)
    
    if total_extracted > 0 or len(all_duplicates) > 0:
        if CONFIG['generate_json_log']:
            generate_audit_log(all_logs, total_extracted, folder_manager, source_info, len(all_duplicates))
        if CONFIG['generate_summary']:
            generate_summary(all_logs, total_extracted, folder_manager, source_info, len(all_duplicates))
        if CONFIG['generate_duplicates_log'] and all_duplicates:
            generate_duplicates_log(all_duplicates, folder_manager)
    else:
        print(f"\n{STRINGS['no_logs']}")

if __name__ == "__main__":
    main()
