#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema Profesional de Evaluación de Autismo - Versión Final Corregida
====================================================================
Versión: 5.3.0
Fecha: 2025-09-17
Características:
- Localización completa sin mezcla de idiomas
- Validación flexible de género (códigos O palabras completas)
- Logs solo en archivo (consola limpia)
- Tabla ordenada de respuestas detalladas
- Selección automática/manual de instrumento
"""
import os
import sys
import json
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# CONFIGURACIÓN PRINCIPAL
CONFIG = {
    'VERSION': '5.3.0',
    'DEFAULT_LANGUAGE': 'es',
    'AVAILABLE_LANGUAGES': ['es', 'en'],
    'TRANSLATIONS_FOLDER': 'locales',
    'TESTS_DATA_FOLDER': 'tests_data',
    'LOGS_FOLDER': 'logs',
    'RESULTS_FOLDER': 'results',
    'FILE_FORMAT': 'json',
    'ENCODING': 'utf-8',
    'CREATE_MISSING_FOLDERS': True,
    'ENABLE_LOGGING': True,
    'LOG_LEVEL': 'INFO',
    'BACKUP_ON_ERROR': True,
    'MAX_RETRY_ATTEMPTS': 3,
    'MOSTRAR_PUNTAJE': True,
    'MOSTRAR_DESGLOSE_DETALLADO': True,
    'USAR_UMBRALES_POR_GENERO': True,
    'ANONIMIZAR_DATOS': True,
    'ALLOW_MANUAL_INSTRUMENT_SELECTION': True,
    'SAVE_USER_PREFERENCES': True,
    'PREFERENCES_FILE': 'user_preferences.json',
    'VALIDATE_AGE_RANGES': True,
    'SHOW_AGE_WARNINGS': True
}

class LogManager:
    """Maneja logging profesional del sistema - Solo logs a archivo"""
    
    def __init__(self):
        self.logger = None
        self.setup_logging()
    
    def setup_logging(self):
        """Configura logging SOLO a archivo, sin mostrar en consola"""
        try:
            if CONFIG['CREATE_MISSING_FOLDERS']:
                Path(CONFIG['LOGS_FOLDER']).mkdir(exist_ok=True)
            
            log_filename = os.path.join(
                CONFIG['LOGS_FOLDER'], 
                f"autism_evaluator_{datetime.now().strftime('%Y%m%d')}.log"
            )
            
            # Configurar logging SOLO para archivo (sin StreamHandler)
            logging.basicConfig(
                level=getattr(logging, CONFIG['LOG_LEVEL']),
                format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                filename=log_filename,
                filemode='a',
                encoding=CONFIG['ENCODING']
            )
            
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Sistema iniciado - Versión {CONFIG['VERSION']}")
            
        except Exception as e:
            # Solo mostrar errores críticos de logging en consola
            print(f"⚠️  Error configurando logging: {e}")
            self.logger = logging.getLogger(__name__)
    
    def log_error(self, error: Exception, context: str = ""):
        """Registra errores con contexto detallado"""
        if self.logger:
            self.logger.error(f"{context}: {str(error)}")
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
    
    def log_info(self, message: str):
        """Registra información general - SOLO en archivo"""
        if self.logger:
            self.logger.info(message)
    
    def log_warning(self, message: str):
        """Registra advertencias - SOLO en archivo"""
        if self.logger:
            self.logger.warning(message)
    
    def log_critical_error(self, message: str):
        """Para errores críticos que SÍ deben mostrarse en consola"""
        if self.logger:
            self.logger.critical(message)
        print(f"💥 ERROR CRÍTICO: {message}")

class FileManager:
    """Maneja operaciones de archivos con manejo robusto de errores"""
    
    def __init__(self, log_manager: LogManager):
        self.log_manager = log_manager
        self.ensure_directories()
    
    def ensure_directories(self):
        """Crea directorios necesarios con manejo de errores"""
        directories = [
            CONFIG['TRANSLATIONS_FOLDER'],
            CONFIG['TESTS_DATA_FOLDER'], 
            CONFIG['LOGS_FOLDER'],
            CONFIG['RESULTS_FOLDER']
        ]
        
        for directory in directories:
            try:
                Path(directory).mkdir(exist_ok=True)
                self.log_manager.log_info(f"Directorio verificado/creado: {directory}")
            except PermissionError:
                self.log_manager.log_error(
                    PermissionError(f"Sin permisos para crear {directory}"),
                    "ensure_directories"
                )
            except OSError as e:
                self.log_manager.log_error(e, f"Error creando directorio {directory}")
    
    def read_json_file(self, filepath: str, retry_count: int = 0) -> Optional[Dict]:
        """Lee archivo JSON con manejo robusto de errores y reintentos"""
        try:
            with open(filepath, 'r', encoding=CONFIG['ENCODING']) as file:
                data = json.load(file)
                self.log_manager.log_info(f"Archivo JSON leído exitosamente: {filepath}")
                return data
                
        except FileNotFoundError:
            error_msg = f"Archivo no encontrado: {filepath}"
            self.log_manager.log_error(FileNotFoundError(error_msg), "read_json_file")
            return None
            
        except json.JSONDecodeError as e:
            error_msg = f"Error decodificando JSON en {filepath}: {e}"
            self.log_manager.log_error(json.JSONDecodeError(error_msg, e.doc, e.pos), "read_json_file")
            return None
            
        except Exception as e:
            error_msg = f"Error inesperado leyendo {filepath}: {e}"
            self.log_manager.log_error(e, "read_json_file")
            return None
    
    def write_file(self, filepath: str, content: str, retry_count: int = 0) -> bool:
        """Escribe archivo con manejo robusto de errores y backup"""
        try:
            if CONFIG['BACKUP_ON_ERROR'] and os.path.exists(filepath):
                backup_path = f"{filepath}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                try:
                    with open(filepath, 'r', encoding=CONFIG['ENCODING']) as original:
                        with open(backup_path, 'w', encoding=CONFIG['ENCODING']) as backup:
                            backup.write(original.read())
                    self.log_manager.log_info(f"Backup creado: {backup_path}")
                except Exception as backup_error:
                    self.log_manager.log_warning(f"No se pudo crear backup: {backup_error}")
            
            with open(filepath, 'w', encoding=CONFIG['ENCODING']) as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            
            self.log_manager.log_info(f"Archivo escrito exitosamente: {filepath}")
            return True
            
        except Exception as e:
            error_msg = f"Error inesperado escribiendo {filepath}: {e}"
            self.log_manager.log_error(e, "write_file")
            return False

class LocalizationManager:
    """Maneja localización completa del sistema"""
    
    def __init__(self, file_manager: FileManager, log_manager: LogManager):
        self.file_manager = file_manager
        self.log_manager = log_manager
        self.current_language = CONFIG['DEFAULT_LANGUAGE']
        self.translations = {}
        self.tests_data = {}
        self.load_all_translations()
        self.load_all_tests_data()
    
    def load_all_translations(self):
        """Carga todas las traducciones disponibles"""
        for language in CONFIG['AVAILABLE_LANGUAGES']:
            success = self.load_language_translations(language)
            if not success and language == CONFIG['DEFAULT_LANGUAGE']:
                self.create_fallback_translations()
    
    def load_language_translations(self, language: str) -> bool:
        """Carga traducciones para un idioma específico"""
        filename = f"{language}.{CONFIG['FILE_FORMAT']}"
        filepath = os.path.join(CONFIG['TRANSLATIONS_FOLDER'], filename)
        
        try:
            data = self.file_manager.read_json_file(filepath)
            if data:
                self.translations[language] = data
                self.log_manager.log_info(f"Traducciones cargadas para idioma: {language}")
                return True
            else:
                self.log_manager.log_warning(f"No se pudieron cargar traducciones para: {language}")
                return False
                
        except Exception as e:
            self.log_manager.log_error(e, f"load_language_translations({language})")
            return False
    
    def load_all_tests_data(self):
        """Carga datos de tests en todos los idiomas"""
        for language in CONFIG['AVAILABLE_LANGUAGES']:
            self.load_tests_data_for_language(language)
    
    def load_tests_data_for_language(self, language: str):
        """Carga datos de tests para un idioma específico"""
        filename = f"tests_{language}.{CONFIG['FILE_FORMAT']}"
        filepath = os.path.join(CONFIG['TESTS_DATA_FOLDER'], filename)
        
        try:
            data = self.file_manager.read_json_file(filepath)
            if data:
                self.tests_data[language] = data
                self.log_manager.log_info(f"Datos de tests cargados para idioma: {language}")
            else:
                self.log_manager.log_warning(f"No se pudieron cargar datos de tests para: {language}")
                if language == CONFIG['DEFAULT_LANGUAGE']:
                    self.create_fallback_tests_data()
                    
        except Exception as e:
            self.log_manager.log_error(e, f"load_tests_data_for_language({language})")
    
    def create_fallback_translations(self):
        """Crea traducciones básicas como fallback"""
        fallback_translations = {
            "system": {
                "title": "Sistema de Evaluación de Autismo",
                "version": f"Versión {CONFIG['VERSION']}",
                "language_selected": "Idioma seleccionado",
                "goodbye": "Hasta luego",
                "evaluation_cancelled": "Evaluación cancelada",
                "interrupted": "Evaluación interrumpida",
                "generated_by": "Generado por",
                "available_instruments": "Instrumentos disponibles",
                "medical_disclaimer": "⚠️ IMPORTANTE: Este NO es un diagnóstico médico"
            },
            "ui": {
                "participant_data": "Datos del Participante",
                "participant_name": "Nombre del participante",
                "age": "Edad",
                "age_input": "Información de Edad",
                "age_prompt": "Edad del participante",
                "age_unit": "Unidad de edad",
                "select_unit": "Seleccione unidad",
                "age_suggestion_months": "💡 Sugerencia: {age} parece ser en meses",
                "age_suggestion_years": "💡 Sugerencia: {age} parece ser en años",
                "gender": "Género",
                "male": "Hombre",
                "female": "Mujer",
                "non_binary": "No binario",
                "prefer_not_answer": "Prefiero no responder",
                "evaluator": "Evaluador",
                "select_option": "Seleccione opción",
                "code_or_word": "código o palabra completa",
                "continue_question": "¿Desea continuar con la evaluación?",
                "selected_test": "Test seleccionado",
                "total_questions": "Total de preguntas",
                "start_evaluation": "¿Desea comenzar la evaluación?",
                "question": "Pregunta",
                "response_options": "Opciones de respuesta",
                "your_response": "Su respuesta",
                "progress": "Progreso",
                "results": "Resultados",
                "participant": "Participante",
                "test": "Test",
                "score": "Puntaje",
                "interpretation": "Interpretación",
                "language": "Idioma",
                "responses": "Respuestas",
                "date": "Fecha",
                "results_saved": "Resultados guardados",
                "new_evaluation": "¿Realizar otra evaluación?",
                "instrument_selection_mode": "Modo de Selección de Instrumento",
                "automatic_selection": "Selección Automática",
                "manual_selection": "Selección Manual",
                "select_mode": "Seleccione modo",
                "automatic_recommendation": "Recomendación Automática",
                "using_automatic": "Usando selección automática",
                "manual_selection_mode": "Modo de selección manual activado",
                "instrument_selected": "Instrumento seleccionado",
                "available_instruments": "Instrumentos Disponibles",
                "select_instrument": "Seleccione instrumento",
                "selection_summary": "Resumen de Selección",
                "system_chooses_age": "El sistema elige según la edad",
                "continue_with_instrument": "¿Desea continuar con {instrument}?"
            },
            "results": {
                "high_risk": "Alto riesgo - Evaluación profesional recomendada",
                "medium_risk": "Riesgo moderado - Seguimiento recomendado",
                "low_risk": "Bajo riesgo"
            },
            "errors": {
                "invalid_age": "Edad debe ser mayor a 0",
                "invalid_number": "Por favor ingrese un número válido",
                "invalid_option": "Opción inválida",
                "invalid_range": "Número fuera de rango",
                "test_data_not_found": "No se encontraron datos del test",
                "invalid_gender": "Opción inválida. Ingrese el código (H/M/NB/NR) o la palabra completa"
            }
        }
        
        self.translations[CONFIG['DEFAULT_LANGUAGE']] = fallback_translations
        self.log_manager.log_info("Traducciones fallback creadas")
    
    def create_fallback_tests_data(self):
        """Crea datos básicos de tests como fallback"""
        fallback_tests = {
            "M-CHAT-R": {
                "name": "M-CHAT-R",
                "full_name": "Lista de Verificación Modificada para Autismo en Niños Pequeños",
                "age_range": [16, 30, "meses"],
                "questions": [
                    "¿Su hijo/a disfruta cuando lo/la mecen?",
                    "¿Su hijo/a se interesa por otros niños?"
                ],
                "response_options": {
                    "si": "Sí",
                    "no": "No"
                }
            }
        }
        
        self.tests_data[CONFIG['DEFAULT_LANGUAGE']] = fallback_tests
        self.log_manager.log_info("Datos de tests fallback creados")
    
    def set_language(self, language: str) -> bool:
        """Cambia el idioma activo"""
        if language in self.translations and language in self.tests_data:
            self.current_language = language
            self.log_manager.log_info(f"Idioma cambiado a: {language}")
            return True
        else:
            self.log_manager.log_warning(f"Idioma no disponible: {language}")
            return False
    
    def get_text(self, key_path: str, default: str = None, **kwargs) -> str:
        """Obtiene texto traducido usando ruta de clave con soporte para formato"""
        try:
            keys = key_path.split('.')
            current_data = self.translations.get(self.current_language, {})
            
            for key in keys:
                if isinstance(current_data, dict) and key in current_data:
                    current_data = current_data[key]
                else:
                    raise KeyError(f"Clave no encontrada: {key_path}")
            
            text = str(current_data) if current_data is not None else (default or key_path)
            
            # Aplicar formateo si se proporcionan kwargs
            if kwargs:
                try:
                    text = text.format(**kwargs)
                except KeyError:
                    pass  # Si falla el formateo, devolver texto sin formatear
            
            return text
            
        except Exception as e:
            self.log_manager.log_warning(f"Error obteniendo traducción para '{key_path}': {e}")
            return default or key_path
    
    def get_test_data(self, test_name: str) -> Optional[Dict]:
        """Obtiene datos de test para el idioma actual"""
        try:
            test_data = self.tests_data.get(self.current_language, {}).get(test_name)
            if test_data:
                return test_data
            else:
                fallback_data = self.tests_data.get(CONFIG['DEFAULT_LANGUAGE'], {}).get(test_name)
                if fallback_data:
                    self.log_manager.log_warning(f"Usando datos fallback para test {test_name}")
                    return fallback_data
                return None
                
        except Exception as e:
            self.log_manager.log_error(e, f"get_test_data({test_name})")
            return None
    
    def get_available_languages(self) -> List[str]:
        """Retorna lista de idiomas disponibles"""
        return [lang for lang in CONFIG['AVAILABLE_LANGUAGES'] 
                if lang in self.translations and lang in self.tests_data]

class InstrumentManager:
    """Maneja la lógica de selección de instrumentos"""
    
    def __init__(self, localization_manager, log_manager):
        self.localization = localization_manager
        self.log_manager = log_manager
        
        self.available_instruments = {
            'M-CHAT-R': {
                'name': 'M-CHAT-R',
                'age_range_years': (1.3, 3.0),
                'recommended_for': 'Niños pequeños (16-36 meses)',
                'description': 'Detección temprana de señales de autismo'
            },
            'AQ-Child': {
                'name': 'AQ-Child',
                'age_range_years': (4, 11),
                'recommended_for': 'Niños (4-11 años)',
                'description': 'Evaluación de características del espectro autista en niños'
            },
            'AQ-Adolescent': {
                'name': 'AQ-Adolescent',
                'age_range_years': (12, 15),
                'recommended_for': 'Adolescentes (12-15 años)',
                'description': 'Adaptado para características de la adolescencia'
            },
            'AQ-Adult': {
                'name': 'AQ-Adult',
                'age_range_years': (16, 100),
                'recommended_for': 'Adultos (16+ años)',
                'description': 'Evaluación comprehensiva para adultos'
            }
        }

    def get_age_with_unit(self) -> Tuple[float, str]:
        """Obtiene edad con unidad clarificada"""
        print(f"\n📅 {self.localization.get_text('ui.age_input', 'Información de Edad')}:")
        print("-" * 50)
        
        while True:
            try:
                edad_input = input(f"{self.localization.get_text('ui.age_prompt', 'Edad del participante')}: ").strip()
                edad_numero = float(edad_input)
                
                if edad_numero <= 0:
                    print(f"❌ {self.localization.get_text('errors.invalid_age', 'La edad debe ser mayor a 0')}")
                    continue
                
                if edad_numero <= 48:
                    mensaje_sugerencia = self.localization.get_text('ui.age_suggestion_months', 
                        "💡 Sugerencia: {age} parece ser en meses", age=edad_numero)
                else:
                    mensaje_sugerencia = self.localization.get_text('ui.age_suggestion_years', 
                        "💡 Sugerencia: {age} parece ser en años", age=edad_numero)
                
                print(f"\n{mensaje_sugerencia}")
                
                unidad_opciones = {
                    'M': f"Meses ({edad_numero} meses = {edad_numero/12:.1f} años)",
                    'A': f"Años ({edad_numero} años = {edad_numero*12:.0f} meses)"
                }
                
                print(f"\n{self.localization.get_text('ui.age_unit', 'Unidad de edad')}:")
                for codigo, descripcion in unidad_opciones.items():
                    print(f"   {codigo}. {descripcion}")
                
                unidad = input(f"\n{self.localization.get_text('ui.select_unit', 'Seleccione unidad')} (M/A): ").strip().upper()
                
                if unidad == 'M':
                    edad_en_años = edad_numero / 12
                    unidad_texto = "meses"
                elif unidad == 'A':
                    edad_en_años = edad_numero
                    unidad_texto = "años"
                else:
                    print(f"❌ {self.localization.get_text('errors.invalid_option', 'Opción inválida')}")
                    continue
                
                return edad_en_años, unidad_texto
                
            except ValueError:
                print(f"❌ {self.localization.get_text('errors.invalid_number', 'Por favor ingrese un número válido')}")

    def determine_automatic_instrument(self, age_in_years: float) -> str:
        """Determina instrumento automáticamente basado en edad"""
        for instrument_name, info in self.available_instruments.items():
            min_age, max_age = info['age_range_years']
            if min_age <= age_in_years <= max_age:
                return instrument_name
        
        if age_in_years < 1.3:
            return 'M-CHAT-R'
        else:
            return 'AQ-Adult'

    def select_instrument(self, age_in_years: float) -> Tuple[str, str]:
        """Método principal para selección de instrumento"""
        auto_instrument = self.determine_automatic_instrument(age_in_years)
        auto_info = self.available_instruments[auto_instrument]
        
        print(f"\n🤖 {self.localization.get_text('ui.automatic_recommendation', 'Recomendación Automática')}:")
        print(f"   📋 Instrumento: {auto_instrument}")
        print(f"   📊 Basado en edad: {age_in_years:.1f} años")
        print(f"   🎯 Rango del instrumento: {auto_info['age_range_years'][0]}-{auto_info['age_range_years'][1]} años")
        
        if not CONFIG['ALLOW_MANUAL_INSTRUMENT_SELECTION']:
            return auto_instrument, "automática"
        
        print(f"\n🔧 {self.localization.get_text('ui.instrument_selection_mode', 'Modo de Selección de Instrumento')}:")
        print("-" * 60)
        print(f"1. 🤖 {self.localization.get_text('ui.automatic_selection', 'Selección Automática')}: {self.localization.get_text('ui.system_chooses_age', 'El sistema elige según la edad')}")
        print(f"2. 👤 {self.localization.get_text('ui.manual_selection', 'Selección Manual')}: Usted elige el instrumento")
        
        while True:
            seleccion = input(f"\n{self.localization.get_text('ui.select_mode', 'Seleccione modo')} (1/2): ").strip()
            
            if seleccion == '1':
                print(f"\n✅ {self.localization.get_text('ui.using_automatic', 'Usando selección automática')}: {auto_instrument}")
                return auto_instrument, "automática"
            elif seleccion == '2':
                manual_instrument = self.get_manual_instrument_selection(age_in_years)
                print(f"\n✅ {self.localization.get_text('ui.instrument_selected', 'Instrumento seleccionado')}: {manual_instrument}")
                return manual_instrument, "manual"
            else:
                print(f"❌ {self.localization.get_text('errors.invalid_option', 'Por favor seleccione 1 o 2')}")
    
    def get_manual_instrument_selection(self, current_age_years: float) -> str:
        """Permite al usuario seleccionar instrumento manualmente"""
        print(f"\n📋 {self.localization.get_text('ui.available_instruments', 'Instrumentos Disponibles')}:")
        print("=" * 80)
        
        instruments_list = list(self.available_instruments.keys())
        
        for i, (instrument_key, info) in enumerate(self.available_instruments.items(), 1):
            min_age, max_age = info['age_range_years']
            
            if min_age <= current_age_years <= max_age:
                status_icon = "✅ RECOMENDADO"
            else:
                status_icon = "❌ FUERA DE RANGO"
            
            print(f"{i}. {info['name']}")
            print(f"   📊 Rango: {min_age}-{max_age} años")
            print(f"   🎯 Para: {info['recommended_for']}")
            print(f"   📝 {info['description']}")
            print(f"   {status_icon} (Edad actual: {current_age_years:.1f} años)")
            print()
        
        while True:
            try:
                seleccion = int(input(f"{self.localization.get_text('ui.select_instrument', 'Seleccione instrumento')} (1-{len(instruments_list)}): "))
                
                if 1 <= seleccion <= len(instruments_list):
                    selected_instrument = instruments_list[seleccion - 1]
                    
                    if CONFIG['VALIDATE_AGE_RANGES']:
                        instrument_info = self.available_instruments[selected_instrument]
                        min_age, max_age = instrument_info['age_range_years']
                        
                        if not (min_age <= current_age_years <= max_age):
                            if CONFIG['SHOW_AGE_WARNINGS']:
                                print(f"\n⚠️  ADVERTENCIA:")
                                print(f"   La edad {current_age_years:.1f} años está fuera del rango recomendado")
                                print(f"   para {selected_instrument} ({min_age}-{max_age} años)")
                                
                                continuar_text = self.localization.get_text('ui.continue_with_instrument', 
                                    "¿Desea continuar con {instrument}?", instrument=selected_instrument)
                                continuar = input(f"\n{continuar_text} (s/n): ").lower()
                                if continuar != 's':
                                    continue
                    
                    return selected_instrument
                else:
                    print(f"❌ {self.localization.get_text('errors.invalid_range', 'Número fuera de rango')}")
                    
            except ValueError:
                print(f"❌ {self.localization.get_text('errors.invalid_number', 'Por favor ingrese un número válido')}")

class EvaluadorAutismoCompleto:
    """Sistema principal con localización completa y selección flexible"""
    
    def __init__(self):
        try:
            self.log_manager = LogManager()
            self.file_manager = FileManager(self.log_manager)
            self.localization = LocalizationManager(self.file_manager, self.log_manager)
            self.instrument_manager = InstrumentManager(self.localization, self.log_manager)
            
            # Variables de sesión
            self.datos_participante = {}
            self.test_actual = None
            self.metodo_seleccion = None
            self.respuestas = []
            self.puntaje_final = 0
            
            self.log_manager.log_info("Sistema inicializado correctamente")
            
        except Exception as e:
            print(f"❌ Error crítico inicializando sistema: {e}")
            sys.exit(1)
    
    def mostrar_selector_idioma(self):
        """Permite al usuario seleccionar idioma"""
        idiomas_disponibles = self.localization.get_available_languages()
        
        if len(idiomas_disponibles) > 1:
            print("\n🌍 SELECCIÓN DE IDIOMA / LANGUAGE SELECTION:")
            print("-" * 50)
            
            for i, idioma in enumerate(idiomas_disponibles, 1):
                nombre_idioma = {
                    'es': 'Español',
                    'en': 'English'
                }.get(idioma, idioma.upper())
                
                print(f"   {i}. {nombre_idioma} ({idioma})")
            
            while True:
                try:
                    seleccion = int(input(f"\n🌐 Seleccione idioma (1-{len(idiomas_disponibles)}): "))
                    if 1 <= seleccion <= len(idiomas_disponibles):
                        idioma_seleccionado = idiomas_disponibles[seleccion - 1]
                        self.localization.set_language(idioma_seleccionado)
                        print(f"✅ {self.localization.get_text('system.language_selected', 'Idioma seleccionado')}: {idioma_seleccionado}")
                        break
                    else:
                        print("❌ Selección inválida")
                except ValueError:
                    print("❌ Por favor ingrese un número válido")
                except KeyboardInterrupt:
                    print(f"\n👋 {self.localization.get_text('system.goodbye', 'Hasta luego')}")
                    sys.exit(0)
    
    def mostrar_header_localizado(self):
        """Header completamente localizado"""
        titulo = self.localization.get_text('system.title', 'Sistema de Evaluación de Autismo')
        version = self.localization.get_text('system.version', f'Versión {CONFIG["VERSION"]}')
        
        print("="*90)
        print(f"🧠 {titulo}")
        print(f"📋 {version}")
        print("="*90)
        
        instrumentos_text = self.localization.get_text('system.available_instruments', 'Instrumentos disponibles')
        print(f"📊 {instrumentos_text}:")
        
        tests_disponibles = ['M-CHAT-R', 'AQ-Child', 'AQ-Adolescent', 'AQ-Adult']
        for test in tests_disponibles:
            test_data = self.localization.get_test_data(test)
            if test_data:
                nombre_completo = test_data.get('full_name', test)
                rango_edad = test_data.get('age_range', ['', '', ''])
                print(f"   • {test}: {nombre_completo} ({rango_edad[0]}-{rango_edad[1]} {rango_edad[2]})")
        
        print("="*90)
        
        disclaimer = self.localization.get_text('system.medical_disclaimer', 
            '⚠️  IMPORTANTE: Este NO es un diagnóstico médico - Solo herramienta de SCREENING')
        print(f"{disclaimer}")
        print("="*90)

    def obtener_datos_participante_completo(self):
        """Obtiene datos del participante con selección flexible de instrumento"""
        print(f"\n👤 {self.localization.get_text('ui.participant_data', 'DATOS DEL PARTICIPANTE')}:")
        print("=" * 60)
        
        # Nombre
        nombre_prompt = self.localization.get_text('ui.participant_name', 'Nombre del participante')
        self.datos_participante['nombre'] = input(f"{nombre_prompt}: ").strip()
        
        # Edad con unidad clarificada
        edad_en_años, unidad_texto = self.instrument_manager.get_age_with_unit()
        self.datos_participante['edad_años'] = edad_en_años
        self.datos_participante['edad_display'] = f"{edad_en_años:.1f} años"
        self.datos_participante['unidad_original'] = unidad_texto
        
        # Selección de instrumento
        self.test_actual, self.metodo_seleccion = self.instrument_manager.select_instrument(edad_en_años)
        
        # Género con validación mejorada (acepta códigos O palabras completas)
        genero_prompt = self.localization.get_text('ui.gender', 'Género')
        opciones_genero = {
            'H': self.localization.get_text('ui.male', 'Hombre'),
            'M': self.localization.get_text('ui.female', 'Mujer'),
            'NB': self.localization.get_text('ui.non_binary', 'No binario'),
            'NR': self.localization.get_text('ui.prefer_not_answer', 'Prefiero no responder')
        }
        
        # Crear mapas inversos para buscar por palabra completa
        opciones_por_palabra = {v.lower(): k for k, v in opciones_genero.items()}
        if self.localization.current_language == 'en':
            # Agregar opciones en inglés también
            opciones_por_palabra.update({
                'male': 'H',
                'female': 'M', 
                'non-binary': 'NB',
                'nonbinary': 'NB',
                'prefer not to answer': 'NR',
                'prefer not answer': 'NR'
            })
        
        print(f"\n👥 {genero_prompt}:")
        for codigo, descripcion in opciones_genero.items():
            print(f"   {codigo}. {descripcion}")
        
        while True:
            genero_input = input(f"\n{self.localization.get_text('ui.select_option', 'Seleccione opción')} ({self.localization.get_text('ui.code_or_word', 'código o palabra completa')}): ").strip()
            
            # Intentar como código directo
            if genero_input.upper() in opciones_genero:
                genero_codigo = genero_input.upper()
                self.datos_participante['genero'] = genero_codigo
                self.datos_participante['genero_descripcion'] = opciones_genero[genero_codigo]
                break
            # Intentar como palabra completa
            elif genero_input.lower() in opciones_por_palabra:
                genero_codigo = opciones_por_palabra[genero_input.lower()]
                self.datos_participante['genero'] = genero_codigo
                self.datos_participante['genero_descripcion'] = opciones_genero[genero_codigo]
                break
            else:
                error_msg = self.localization.get_text('errors.invalid_gender', 
                    'Opción inválida. Ingrese el código (H/M/NB/NR) o la palabra completa')
                print(f"❌ {error_msg}")
        
        # Evaluador
        evaluador_prompt = self.localization.get_text('ui.evaluator', 'Evaluador')
        self.datos_participante['evaluador'] = input(f"\n👨‍⚕️ {evaluador_prompt}: ").strip()

    def mostrar_resumen_seleccion(self) -> bool:
        """Muestra resumen de la selección realizada"""
        print(f"\n📋 {self.localization.get_text('ui.selection_summary', 'RESUMEN DE SELECCIÓN')}:")
        print("=" * 60)
        print(f"👤 Participante: {self.datos_participante['nombre']}")
        print(f"📅 Edad: {self.datos_participante['edad_display']} (unidad original: {self.datos_participante['unidad_original']})")
        print(f"👥 Género: {self.datos_participante['genero_descripcion']}")
        print(f"🔬 Instrumento: {self.test_actual}")
        print(f"⚙️  Método de selección: {self.metodo_seleccion}")
        print(f"👨‍⚕️ Evaluador: {self.datos_participante['evaluador']}")
        
        instrument_info = self.instrument_manager.available_instruments[self.test_actual]
        print(f"\n📊 Información del Instrumento:")
        print(f"   Rango de edad: {instrument_info['age_range_years'][0]}-{instrument_info['age_range_years'][1]} años")
        print(f"   Descripción: {instrument_info['description']}")
        
        confirmar = input(f"\n✅ ¿Confirma estos datos para proceder? (s/n): ").lower()
        return confirmar == 's'
    
    def ejecutar_test_localizado(self) -> bool:
        """Ejecuta test con interfaz completamente localizada"""
        test_data = self.localization.get_test_data(self.test_actual)
        
        if not test_data:
            error_msg = self.localization.get_text('errors.test_data_not_found', 
                f'No se encontraron datos para el test {self.test_actual}')
            print(f"❌ {error_msg}")
            return False
        
        print(f"\n🔬 {self.localization.get_text('ui.selected_test', 'Test seleccionado')}: {test_data.get('full_name', self.test_actual)}")
        
        preguntas = test_data.get('questions', [])
        opciones = test_data.get('response_options', {})
        
        print(f"📊 {self.localization.get_text('ui.total_questions', 'Total de preguntas')}: {len(preguntas)}")
        print(f"⏱️  Tiempo estimado: {len(preguntas) * 0.5:.0f} minutos")
        
        inicio_prompt = self.localization.get_text('ui.start_evaluation', '¿Desea comenzar la evaluación?')
        if input(f"\n{inicio_prompt} (s/n): ").lower() != 's':
            return False
        
        # Ejecutar preguntas
        for i, pregunta in enumerate(preguntas, 1):
            print(f"\n{'='*70}")
            print(f"📝 {self.localization.get_text('ui.question', 'Pregunta')} {i}/{len(preguntas)}:")
            print(f"   {pregunta}")
            
            print(f"\n   {self.localization.get_text('ui.response_options', 'Opciones de respuesta')}:")
            opciones_numeradas = {}
            for j, (clave, valor) in enumerate(opciones.items(), 1):
                opciones_numeradas[j] = clave
                puntos_texto = f" ({j-1} pts)" if CONFIG['MOSTRAR_PUNTAJE'] else ""
                print(f"   {j}. {valor}{puntos_texto}")
            
            # Obtener respuesta
            while True:
                try:
                    respuesta_prompt = self.localization.get_text('ui.your_response', 'Su respuesta')
                    respuesta = int(input(f"\n   {respuesta_prompt} (1-{len(opciones)}): "))
                    if 1 <= respuesta <= len(opciones):
                        self.respuestas.append(opciones_numeradas[respuesta])
                        break
                    else:
                        error_msg = self.localization.get_text('errors.invalid_range', 'Número fuera de rango')
                        print(f"❌ {error_msg}")
                except ValueError:
                    error_msg = self.localization.get_text('errors.invalid_number', 'Ingrese un número válido')
                    print(f"❌ {error_msg}")
            
            # Mostrar progreso
            progreso = (i / len(preguntas)) * 100
            progreso_text = self.localization.get_text('ui.progress', 'Progreso')
            print(f"   📈 {progreso_text}: {progreso:.1f}%")
        
        return True
    
    def generar_tabla_respuestas(self, preguntas: List[str]) -> str:
        """Genera tabla ordenada de preguntas y respuestas en formato Markdown"""
        try:
            test_data = self.localization.get_test_data(self.test_actual)
            opciones_respuesta = test_data.get('response_options', {}) if test_data else {}
            
            # Crear encabezado de tabla
            tabla = "| # | Pregunta | Respuesta |\n"
            tabla += "|---|----------|----------|\n"
            
            # Llenar tabla con preguntas y respuestas
            for i, (pregunta, respuesta_clave) in enumerate(zip(preguntas, self.respuestas), 1):
                # Convertir clave de respuesta a texto legible
                respuesta_texto = opciones_respuesta.get(respuesta_clave, respuesta_clave)
                
                # Limpiar texto de pregunta para tabla
                pregunta_limpia = pregunta.replace('\n', ' ').replace('|', '\\|').strip()
                respuesta_limpia = str(respuesta_texto).replace('\n', ' ').replace('|', '\\|').strip()
                
                # Limitar longitud de pregunta si es muy larga
                if len(pregunta_limpia) > 80:
                    pregunta_limpia = pregunta_limpia[:77] + "..."
                
                tabla += f"| {i:02d} | {pregunta_limpia} | **{respuesta_limpia}** |\n"
            
            # Agregar resumen al final
            tabla += f"\n**Resumen:** {len(self.respuestas)} preguntas respondidas | Puntaje total: {self.puntaje_final}\n"
            
            return tabla
            
        except Exception as e:
            self.log_manager.log_error(e, "generar_tabla_respuestas")
            # Fallback a formato simple si hay error
            return f"Respuestas: {', '.join(self.respuestas)}"
    
    def mostrar_resultados_localizados(self) -> bool:
        """Muestra resultados con interfaz localizada"""
        # Calcular puntaje básico
        self.puntaje_final = len([r for r in self.respuestas if r in ['no', 'Si', '4', '3']])
        
        print(f"\n{'='*90}")
        print(f"🎯 {self.localization.get_text('ui.results', 'Resultados')}")
        print(f"{'='*90}")
        
        print(f"👤 {self.localization.get_text('ui.participant', 'Participante')}: {self.datos_participante['nombre']}")
        print(f"🔬 {self.localization.get_text('ui.test', 'Test')}: {self.test_actual}")
        print(f"⚙️  Método selección: {self.metodo_seleccion}")
        print(f"📊 {self.localization.get_text('ui.score', 'Puntaje')}: {self.puntaje_final}")
        
        # Interpretación básica
        if self.puntaje_final >= 8:
            interpretacion = self.localization.get_text('results.high_risk', 'Alto riesgo - Evaluación profesional recomendada')
        elif self.puntaje_final >= 3:
            interpretacion = self.localization.get_text('results.medium_risk', 'Riesgo moderado - Seguimiento recomendado')
        else:
            interpretacion = self.localization.get_text('results.low_risk', 'Bajo riesgo')
        
        print(f"🎯 {self.localization.get_text('ui.interpretation', 'Interpretación')}: {interpretacion}")
        
        # Guardar resultados
        if self.guardar_resultados_localizado():
            guardar_msg = self.localization.get_text('ui.results_saved', 'Resultados guardados exitosamente')
            print(f"💾 {guardar_msg}")
        
        return True
    
    def guardar_resultados_localizado(self) -> bool:
        """Guarda resultados con tabla ordenada de preguntas y respuestas"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_archivo = f"evaluacion_{self.datos_participante['nombre'].replace(' ', '_')}_{timestamp}.md"
            filepath = os.path.join(CONFIG['RESULTS_FOLDER'], nombre_archivo)
            
            # Obtener datos del test para las preguntas
            test_data = self.localization.get_test_data(self.test_actual)
            preguntas = test_data.get('questions', []) if test_data else []
            
            # Crear tabla de respuestas ordenadas
            tabla_respuestas = self.generar_tabla_respuestas(preguntas)
            
            # Crear contenido del reporte mejorado
            contenido = f"""# {self.localization.get_text('system.title', 'Reporte de Evaluación')}

## {self.localization.get_text('ui.participant_data', 'Datos del Participante')}
- **{self.localization.get_text('ui.participant_name', 'Nombre')}:** {self.datos_participante['nombre']}
- **{self.localization.get_text('ui.age', 'Edad')}:** {self.datos_participante.get('edad_display', 'N/A')}
- **{self.localization.get_text('ui.gender', 'Género')}:** {self.datos_participante.get('genero_descripcion', 'N/A')}
- **{self.localization.get_text('ui.evaluator', 'Evaluador')}:** {self.datos_participante.get('evaluador', 'N/A')}
- **{self.localization.get_text('ui.date', 'Fecha')}:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## {self.localization.get_text('ui.results', 'Resultados')}
- **{self.localization.get_text('ui.test', 'Test aplicado')}:** {self.test_actual}
- **Método de selección:** {self.metodo_seleccion}
- **{self.localization.get_text('ui.score', 'Puntaje total')}:** {self.puntaje_final}
- **{self.localization.get_text('ui.language', 'Idioma de evaluación')}:** {self.localization.current_language}

## {self.localization.get_text('ui.responses', 'Respuestas Detalladas')}

{tabla_respuestas}

---
*{self.localization.get_text('system.generated_by', 'Generado por')} {self.localization.get_text('system.title', 'Sistema de Evaluación de Autismo')} v{CONFIG['VERSION']}*
"""
            
            return self.file_manager.write_file(filepath, contenido)
            
        except Exception as e:
            self.log_manager.log_error(e, "guardar_resultados_localizado")
            return False
    
    def ejecutar_evaluacion_localizada(self):
        """Ejecuta evaluación con soporte completo de localización y selección flexible"""
        try:
            # Selección de idioma
            self.mostrar_selector_idioma()
            
            # Header localizado
            self.mostrar_header_localizado()
            
            # Confirmación de términos
            continuar_text = self.localization.get_text('ui.continue_question', 
                '¿Desea continuar con la evaluación?')
            continuar = input(f"\n{continuar_text} (s/n): ").lower()
            
            if continuar != 's':
                despedida = self.localization.get_text('system.evaluation_cancelled', 
                    'Evaluación cancelada')
                print(f"{despedida}")
                return False
            
            # Obtener datos del participante con selección flexible
            self.obtener_datos_participante_completo()
            
            # Mostrar resumen y confirmar
            if not self.mostrar_resumen_seleccion():
                print(f"\n🔄 Reiniciando proceso...")
                return False
            
            # Ejecutar test seleccionado
            if self.ejecutar_test_localizado():
                # Mostrar resultados
                return self.mostrar_resultados_localizados()
            
            return False
            
        except KeyboardInterrupt:
            interrupcion = self.localization.get_text('system.interrupted', 
                'Evaluación interrumpida por el usuario')
            print(f"\n\n👋 {interrupcion}")
            return False
            
        except Exception as e:
            error_msg = self.localization.get_text('errors.unexpected_error', 'Error inesperado')
            print(f"\n❌ {error_msg}: {e}")
            self.log_manager.log_error(e, "ejecutar_evaluacion_localizada")
            return False

def main():
    """Función principal con manejo robusto de errores"""
    try:
        print("🚀 Iniciando Sistema Profesional de Evaluación de Autismo...")
        print("⏳ Cargando localización, instrumentos y datos...")
        
        evaluador = EvaluadorAutismoCompleto()
        
        while True:
            exito = evaluador.ejecutar_evaluacion_localizada()
            
            if not exito:
                break
            
            # Preguntar por nueva evaluación
            nueva_eval = evaluador.localization.get_text('ui.new_evaluation', 
                '¿Realizar otra evaluación?')
            continuar = input(f"\n{nueva_eval} (s/n): ").lower()
            
            if continuar != 's':
                break
            
            # Reiniciar datos para nueva evaluación
            evaluador.datos_participante = {}
            evaluador.test_actual = None
            evaluador.metodo_seleccion = None
            evaluador.respuestas = []
            evaluador.puntaje_final = 0
        
        despedida = evaluador.localization.get_text('system.goodbye', 
            'Gracias por usar el Sistema de Evaluación de Autismo')
        print(f"\n👋 {despedida}")
        
    except KeyboardInterrupt:
        print("\n\n👋 Programa interrumpido por el usuario")
    except Exception as e:
        print(f"\n💥 Error crítico del sistema: {e}")
        logging.error(f"Error crítico: {e}", exc_info=True)
    finally:
        print("🏥 Recuerde: Solo profesionales pueden realizar diagnósticos oficiales")

if __name__ == "__main__":
    main()
