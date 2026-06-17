#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IBM i Unified Auditor
Versión: 20.6.0-final
Suite unificada para IBM i / AS400 - RPG / SQL / DB / CLP / PF / DSPF
No modifica archivos originales. Solo lectura, análisis y generación de reportes.
Incluye manejo robusto de errores y diccionarios mejorados para RPG/CL/SQL.
"""
import argparse
import hashlib
import json
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import chardet
    CHARDET_OK = True
except Exception:
    CHARDET_OK = False

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

APP_NAME = 'IBM i Unified Auditor'
APP_VERSION = '20.6.0-final'
TS_FORMAT = '%Y%m%d_%H%M%S'
SEVERITY_ORDER = {'Alta': 3, 'Media': 2, 'Baja': 1}

TEXT_EXTENSIONS = {
    '.txt', '.cl', '.clp', '.rpgle', '.rpg', '.sqlrpgle', '.sql', 
    '.pf', '.lf', '.dspf', '.src', '.mbr', '.cpy', '.rpgleinc'
}

# ============================================================================
# DICCIONARIOS MEJORADOS
# ============================================================================

# Comandos CL expandidos con todos los parámetros comunes
CL_COMMANDS = {
    'PGM': '[PGM] Inicia un programa CL.',
    'ENDPGM': '[ENDPGM] Finaliza el programa CL.',
    'DCL': '[DCL] Declara variable o parámetro.',
    'DCLF': '[DCLF] Declara archivo para uso en CL.',
    'RTVJOBA': '[RTVJOBA] Recupera atributos del job.',
    'RTVDTAARA': '[RTVDTAARA] Recupera datos desde data area.',
    'CHGDTAARA': '[CHGDTAARA] Actualiza data area.',
    'CHGVAR': '[CHGVAR] Modifica una variable.',
    'CALL': '[CALL] Invoca otro programa.',
    'RUNSQL': '[RUNSQL] Ejecuta sentencia SQL desde CL.',
    'RUNSQLSTM': '[RUNSQLSTM] Ejecuta script SQL desde miembro fuente.',
    'STRQMQRY': '[STRQMQRY] Ejecuta Query Management.',
    'MONMSG': '[MONMSG] Monitorea mensajes.',
    'IF': '[IF] Evalúa una condición.',
    'ELSE': '[ELSE] Rama alternativa de control.',
    'DO': '[DO] Inicia bloque de control.',
    'ENDDO': '[ENDDO] Finaliza bloque de control.',
    'GOTO': '[GOTO] Transfiere control a una etiqueta.',
    'DLYJOB': '[DLYJOB] Suspende el job por un tiempo definido.',
    'CHKOBJ': '[CHKOBJ] Verifica objeto.',
    'OVRDBF': '[OVRDBF] Override de archivo de base de datos.]',
    'DLTOVR': '[DLTOVR] Elimina override activo.',
    'CPYF': '[CPYF] Copia registros de archivo.',
    'CRTPF': '[CRTPF] Crea archivo físico.',
    'SBMJOB': '[SBMJOB] Envía trabajo en batch.',
    'SNDPGMMSG': '[SNDPGMMSG] Envía mensaje al programa.',
    # Nuevos comandos CL
    'ENDSBS': '[ENDSBS] Finaliza un subsistema.',
    'STRSBS': '[STRSBS] Inicia un subsistema.',
    'RCVF': '[RCVF] Recibe registro desde archivo declarado con DCLF.',
    'CLRPFM': '[CLRPFM] Limpia miembro de archivo físico.',
    'RCLRSC': '[RCLRSC] Libera recursos asignados al programa CL.',
    'RETURN': '[RETURN] Retorna desde el programa CL al llamador.',
    'SNDUSRMSG': '[SNDUSRMSG] Envía mensaje a pantalla de usuario.',
    'DSPJOB': '[DSPJOB] Muestra información del job.',
    'WRKOBJ': '[WRKOBJ] Trabaja con objetos.',
    'CRTLIB': '[CRTLIB] Crea librería.',
    'DLTLIB': '[DLTLIB] Elimina librería.',
    'CRTBNDRPG': '[CRTBNDRPG] Compila programa RPG bound.',
    'CRTCLPGM': '[CRTCLPGM] Compila programa CL.',
    'CRTSQLRPGI': '[CRTSQLRPGI] Compila programa SQL RPG.',
    'STRPCCMD': '[STRPCCMD] Ejecuta comando de PC.',
    'ALCOBJ': '[ALCOBJ] Reserva objeto.',
    'DLCOBJ': '[DLCOBJ] Libera objeto reservado.',
    'SNDMSG': '[SNDMSG] Envía mensaje.',
    'RCVMSG': '[RCVMSG] Recibe mensaje.',
}

# Parámetros comunes de comandos CL (para detectar continuaciones)
CL_PARAMS = {
    'VALUE', 'COMMIT', 'MARGINS', 'SRCFILE', 'OPTION', 'SIZE', 'TOFILE', 
    'MBROPT', 'FROMFILE', 'TOPGMQ', 'MSGTYPE', 'MSGDTA', 'MSGF', 'MSGID',
    'RCDFMT', 'OPNID', 'PARM', 'COND', 'THEN', 'EXEC', 'CMDLBL', 'OBJ',
    'OBJTYPE', 'TYPE', 'LEN', 'RTNVAR', 'DTAARA', 'FILE', 'SRCMBR',
    'SBS', 'SBS', 'SBSD', 'DLY', 'LOG', 'JOBQ', 'PRTDEV', 'OUTQ',
    'USER', 'PRTTXT', 'RTGDTA', 'SYSLIBL', 'CURLIB', 'INLLIBL',
    'LOGCLPGM', 'MSGQ', 'SPLFACN', 'IMMED', 'DELAYED',
}

# Tokens RPG expandidos
RPG_TOKENS = [
    'CTL-OPT', 'DCL-F', 'DCL-S', 'DCL-DS', 'DCL-PR', 'DCL-PI', 
    'DCL-PROC', 'END-PROC', 'BEGSR', 'ENDSR', 'CHAIN', 'SETLL', 
    'READE', 'READ', 'WRITE', 'UPDATE', 'DELETE', 'EXSR', 'CALLP',
    'DOW', 'DOU', 'ENDDO', 'SELECT', 'WHEN', 'OTHER', 'ENDSL',
    'IF', 'ELSE', 'ENDIF', 'FOR', 'ENDFOR', 'ITER', 'LEAVE',
    'CLEAR', 'RESET', 'RETURN', 'OPEN', 'CLOSE',
    'EXEC SQL', 'SET OPTION',
]

SQL_TOKENS = [
    'BEGIN', 'DECLARE', 'SELECT', 'UPDATE', 'INSERT', 'DELETE', 
    'MERGE', 'FETCH FIRST', 'ORDER BY', 'WHERE', 'END IF', 'ELSE', 'THEN',
    'INTO', 'FROM', 'VALUES', 'AND', 'OR', 'GROUP BY', 'HAVING',
]

# ============================================================================
# REGLAS DE SEGURIDAD (MOTOR A, B, INFO)
# ============================================================================
RULES_MOTOR_A_PATTERNS = {
    'COMMAND_INJECTION_QCMDEXC': {
        'scope': {'CL'},
        'pattern': r'CALL\s+(?:PGM\(\))?\s+QCMDEXC\s+',
        'descripcion': 'Llamada dinámica a la API QCMDEXC. Si concatena variables sin sanitizar, permite Inyección de Comandos.',
        'categoria': 'Injection / Privilege Escalation',
        'cwe': 'CWE-78',
        'owasp': 'A03:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Evitar concatenación dinámica. Usar validaciones estrictas o llamadas paramétricas nativas.',
        'referencias': ['IBM Doc: QCMDEXC API (https://www.ibm.com/docs/en/i/7.5?topic=ssw_ibm_i_75/api/qcmdexc.htm)']
    },
    'ADOPT_AUTHORITY_POTENTIAL': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF'},
        'pattern': r'(?:USRPRF|USRPH)\s*\(\s*[*]OWNER\s*\)',
        'descripcion': 'Adopt Authority (*OWNER). Riesgo de escalada de privilegios si el dueño tiene *ALLOBJ o *SECADM.',
        'categoria': 'Privilege Management',
        'cwe': 'CWE-250',
        'owasp': 'A04:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Restringir USRPRF(*OWNER). Asegurar controles rigurosos de entrada en programas que lo usen.',
        'referencias': ['IBM Doc: Adopted authority (https://www.ibm.com/docs/en/i/7.5?topic=security-adopted-authority)']
    },
    'PRIVILEGE_ESCALATION_BACKDOOR': {
        'scope': {'CL', 'RPG', 'SQL'},
        'pattern': r'\b(?:CHGUSRPRF|GRTOBJAUT|EDTOBJAUT)\b.*?\b(?:[*]ALLOBJ|[*]SECADM|[*]IOSYSCFG|[*]ALL)\b',
        'descripcion': 'Concesión de autoridades especiales (*ALLOBJ, *SECADM). Mecanismo clásico de backdoor o escalada.',
        'categoria': 'Privilege Escalation / Backdoor',
        'cwe': 'CWE-269',
        'owasp': 'A01:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Auditar estrictamente qué programas ejecutan estos comandos. Restringir a perfiles de emergencia.',
        'referencias': ['IBM Doc: Special Authorities (https://www.ibm.com/docs/en/i/7.5?topic=security-special-authorities)']
    },
    'SQL_INJECTION_VECTOR': {
        'scope': {'CL', 'SQL', 'RPG'},
        'pattern': r'(?:\bSTRQMQRY\b.*?\bSETVAR\b|\bEXECUTE\s+IMMEDIATE\b|\bPREPARE\b)',
        'descripcion': 'SQL dinámico o Query Manager (STRQMQRY con SETVAR). Vulnerable a SQL Injection si no se sanitiza.',
        'categoria': 'Injection',
        'cwe': 'CWE-89',
        'owasp': 'A03:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Usar SQL estático con variables host. Si es dinámico, usar marcadores (?) y PREPARE/EXECUTE.',
        'referencias': ['IBM Doc: STRQMQRY (https://www.ibm.com/docs/en/i/7.5?topic=ssstrqm-start-query-management-query-strqmqry)']
    },
    'HARDCODED_PASSWORDS': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF', 'DESCONOCIDO'},
        'pattern': r'\b(?:PASSWORD|PWD|PASS|CLAVE|SECRET|TOKEN|AUTCHG)\s*[=:]\s*["\']?([^"\'\s;,)]+)',
        'descripcion': 'Posible credencial o llave de servicio incrustada estáticamente en el archivo fuente.',
        'categoria': 'Hardcoded Credentials',
        'cwe': 'CWE-798',
        'owasp': 'A07:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Remover contraseñas en texto claro. Usar VLDL o bóvedas de secretos externas.',
        'referencias': ['CWE-798 (https://cwe.mitre.org/data/definitions/798.html)']
    },
    'HARDCODED_CONNECTION_STRINGS': {
        'scope': {'CL', 'RPG', 'SQL', 'DESCONOCIDO'},
        'pattern': r'(?:jdbc:as400|jdbc:db2|DSN=|Provider=IBMDA400).*?(?:UID|User|PWD|Password)\s*=',
        'descripcion': 'Cadena de conexión a base de datos (JDBC/ODBC) con credenciales incrustadas.',
        'categoria': 'Hardcoded Credentials',
        'cwe': 'CWE-798',
        'owasp': 'A07:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Externalizar cadenas de conexión a archivos con autoridad *PUBLIC *EXCLUDE o VLDL.',
        'referencias': ['IBM Doc: JDBC Connections (https://www.ibm.com/docs/en/i/7.5?topic=developer-toolkit-jdbc)']
    },
    'SECURITY_DOWNGRADE_SYSVAL': {
        'scope': {'CL'},
        'pattern': r'\bCHGSYSVAL\b\s+SYSVAL\(\s*(?:QSECURITY|QMAXSIGN|QAUTOVRT|QPWDRQDLT|QALWOBJRTN)',
        'descripcion': 'Alteración de Valores del Sistema críticos (QSECURITY, QMAXSIGN). Riesgo de degradación de seguridad.',
        'categoria': 'Security Misconfiguration / Downgrade',
        'cwe': 'CWE-284',
        'owasp': 'A05:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Restringir CHGSYSVAL a perfiles *SECADM. Monitorear cambios en el audit log (QAUDLVL).',
        'referencias': ['IBM Doc: System Values (https://www.ibm.com/docs/en/i/7.5?topic=ssw_ibm_i_75/rzank/rzank.pdf)']
    },
    'DYNAMIC_SBMJOB': {
        'scope': {'CL', 'RPG'},
        'pattern': r'SBMJOB\s+CMD\(.*?(?:&|\%TRIM|\%SUBST|CONCAT|\|\|)',
        'descripcion': 'SBMJOB con comando dinámico concatenado. Riesgo de inyección de comandos CL.',
        'categoria': 'Injection / Command Injection',
        'cwe': 'CWE-78',
        'owasp': 'A03:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Validar estrictamente los parámetros antes de construir el comando SBMJOB.',
        'referencias': ['IBM Doc: SBMJOB']
    },
    'EMBEDDED_SQL_DYNAMIC': {
        'scope': {'RPG'},
        'pattern': r'EXEC\s+SQL\s+.*?(?:EXECUTE\s+IMMEDIATE|\|\||\%TRIM.*?SQL)',
        'descripcion': 'SQL embebido con construcción dinámica. Riesgo de SQL Injection.',
        'categoria': 'Injection',
        'cwe': 'CWE-89',
        'owasp': 'A03:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Usar variables host con marcadores (?) y PREPARE/EXECUTE.',
        'referencias': ['IBM Doc: Embedded SQL']
    },
    'DYNAMIC_COMMAND_CONSTRUCTION': {
        'scope': {'CL', 'RPG'},
        'pattern': r'(?:command|cmd|&CMD)\s*(?:=|\+|\|\|)\s*[\'"]?(?:CALL|SBMJOB|RUNSQL|CHG|CRT|DLT|WRK|DSP)',
        'descripcion': 'Construcción dinámica de comandos CL mediante concatenación. Alto riesgo de inyección.',
        'categoria': 'Injection / Command Injection',
        'cwe': 'CWE-78',
        'owasp': 'A03:2021',
        'criticidad': 'Alta',
        'mitigacion': 'Validar estrictamente todos los componentes antes de construir el comando. Usar listas blancas.',
        'referencias': ['CWE-78 (https://cwe.mitre.org/data/definitions/78.html)']
    },
    'SQL_RUNNER_CL': {
        'scope': {'CL'},
        'pattern': r'^\s*(RUNSQL|RUNSQLSTM|STRQMQRY)\b',
        'descripcion': 'Ejecución de SQL o Query Manager desde CL. Revisar parametrización y origen de entrada.',
        'categoria': 'SQL Execution / Review',
        'cwe': 'CWE-89',
        'owasp': 'A03:2021',
        'criticidad': 'Media',
        'mitigacion': 'Preferir SQL controlado y validar el origen de parámetros.',
        'referencias': ['IBM Doc: RUNSQL / RUNSQLSTM / STRQMQRY']
    },
    'DESTRUCTIVE_COMMANDS': {
        'scope': {'CL', 'RPG', 'SQL'},
        'pattern': r'\b(?:DLTF|DLTPGM|CLRLIB|DLTLIB|DLF)\b',
        'descripcion': 'Comandos de destrucción forzada de objetos. Riesgo de DoS lógico si los parámetros son manipulables.',
        'categoria': 'Data Destruction / DoS',
        'cwe': 'CWE-73',
        'owasp': 'A01:2021',
        'criticidad': 'Media',
        'mitigacion': 'Validar nombres de objetos contra una lista blanca rígida antes de la llamada.',
        'referencias': ['IBM Doc: Object Control (https://www.ibm.com/docs/en/i/7.5?topic=commands)']
    },
    'LIBRARY_LIST_MANIPULATION': {
        'scope': {'CL', 'RPG', 'SQL'},
        'pattern': r'\b(?:CHGLIBL|ADDLIBLE|RMVLIBLE|QLICHGLL|CHGJOB\s+.*?LIBL)\b',
        'descripcion': 'Manipulación de *LIBL. Riesgo de Library Hijacking si se inyecta una librería maliciosa.',
        'categoria': 'Insecure Configuration',
        'cwe': 'CWE-427',
        'owasp': 'A05:2021',
        'criticidad': 'Media',
        'mitigacion': 'Calificar de forma absoluta el nombre de la biblioteca (ej: NOM_LIB/NOM_PROG).',
        'referencias': ['IBM Doc: Library lists (*LIBL) (https://www.ibm.com/docs/en/i/7.5?topic=objects-library-list)']
    },
    'DUMP_STATEMENTS': {
        'scope': {'CL', 'RPG'},
        'pattern': r'(?:\bDUMP\b|\bDMPCLPGM\b|CALL\s+[\'"]?DUMP[\'"]?|C\+\s+CALL\s+[\'"]?DUMP)',
        'descripcion': 'Volcado de memoria técnica (DUMP) activo. Expone variables y pila de llamadas en producción.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-215',
        'owasp': 'A05:2021',
        'criticidad': 'Media',
        'mitigacion': 'Eliminar llamadas a DUMP/DMPCLPGM antes de promover a ambientes productivos.',
        'referencias': ['CWE-215 (https://cwe.mitre.org/data/definitions/215.html)']
    },
    'DEBUG_CONFIG': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF'},
        'pattern': r'(?:DEBUG\s*\(\s*[*]YES\s*\)|CHGJOB\s+.*DEBUG\s*\(\s*[*]YES\s*\)|CTL-OPT\s+.*DEBUG\s*\(\s*[*]YES\s*\))',
        'descripcion': 'Depuración interactiva habilitada (DEBUG(*YES)). Facilita ingeniería inversa.',
        'categoria': 'Insecure Configuration',
        'cwe': 'CWE-489',
        'owasp': 'A05:2021',
        'criticidad': 'Media',
        'mitigacion': 'Garantizar que la directiva de compilación sea DEBUG(*NO) en producción.',
        'referencias': ['CWE-489 (https://cwe.mitre.org/data/definitions/489.html)']
    },
    'RPG_DEBUG_STATEMENTS': {
        'scope': {'RPG'},
        'pattern': r'(?:^|\s)DEBUG\s*(?:=|:|\()',
        'descripcion': 'Instrucción de depuración explícita (DEBUG = ON, DEBUG: ON) en código RPG. Permite depuración activa en producción.',
        'categoria': 'Insecure Debug/Configuration',
        'cwe': 'CWE-489',
        'owasp': 'A05:2021',
        'criticidad': 'Media',
        'mitigacion': 'Remover instrucciones DEBUG antes de promover a producción. Usar DEBUG(*NO) en CTL-OPT.',
        'referencias': ['CWE-489 (https://cwe.mitre.org/data/definitions/489.html)']
    },
    'AUDIT_EVASION_JOURNAL': {
        'scope': {'CL', 'RPG', 'SQL'},
        'pattern': r'\b(?:ENDJRNPF|ENDJRN|CHGJRN|DLTSPLF)\b',
        'descripcion': 'Detener journaling (ENDJRNPF) o borrar spool files (DLTSPLF). Busca ocultar manipulaciones.',
        'categoria': 'Audit Evasion / Anti-Forensics',
        'cwe': 'CWE-778',
        'owasp': 'A09:2021',
        'criticidad': 'Media',
        'mitigacion': 'Restringir acceso a comandos de control de journals. Configurar journals críticos como inalterables.',
        'referencias': ['IBM Doc: ENDJRNPF (https://www.ibm.com/docs/en/i/7.5?topic=ssendjrn-end-journal-physical-file-endjrn)']
    },
    'DATA_EXFILTRATION_NETWORK': {
        'scope': {'CL', 'RPG', 'SQL'},
        'pattern': r'\b(?:FTP|SNDDST|CPYTOSTMF)\b',
        'descripcion': 'Transferencia de red (FTP, SNDDST, CPYTOSTMF). Riesgo alto de exfiltración de datos.',
        'categoria': 'Data Exfiltration',
        'cwe': 'CWE-200',
        'owasp': 'A01:2021',
        'criticidad': 'Media',
        'mitigacion': 'Validar destinos contra lista blanca. Preferir SFTP. Revisar que no haya credenciales en el script.',
        'referencias': ['IBM Doc: SNDDST (https://www.ibm.com/docs/en/i/7.5?topic=sssnddst-send-distribution-snddst)']
    },
    'DESTRUCTIVE_CLRPFM': {
        'scope': {'CL'},
        'pattern': r'\bCLRPFM\b',
        'descripcion': 'Limpieza de miembro de archivo físico. Riesgo de pérdida de datos si los parámetros son manipulables.',
        'categoria': 'Data Destruction / DoS',
        'cwe': 'CWE-73',
        'owasp': 'A01:2021',
        'criticidad': 'Media',
        'mitigacion': 'Validar nombres de archivo/miembro contra lista blanca. Confirmar antes de ejecutar.',
        'referencias': ['IBM Doc: CLRPFM']
    },
    'SUBSYSTEM_CONTROL': {
        'scope': {'CL'},
        'pattern': r'\b(?:ENDSBS|STRSBS|ENDSBSNB)\b',
        'descripcion': 'Control de subsistemas (inicio/fin). Puede causar DoS si se ejecuta con parámetros manipulables.',
        'categoria': 'Availability / DoS',
        'cwe': 'CWE-400',
        'owasp': 'A01:2021',
        'criticidad': 'Media',
        'mitigacion': 'Restringir ejecución a perfiles administrativos. Validar nombres de subsistema.',
        'referencias': ['IBM Doc: ENDSBS/STRSBS']
    },
    'CPYF_REPLACE_RISK': {
        'scope': {'CL'},
        'pattern': r'\bCPYF\b.*?MBROPT\(\s*\*REPLACE\s*\)',
        'descripcion': 'CPYF con opción *REPLACE. Sobrescribe datos existentes sin backup previo.',
        'categoria': 'Data Destruction / DoS',
        'cwe': 'CWE-73',
        'owasp': 'A01:2021',
        'criticidad': 'Media',
        'mitigacion': 'Validar origen/destino. Considerar backup previo. Usar *ADD en lugar de *REPLACE cuando sea posible.',
        'referencias': ['IBM Doc: CPYF']
    },
    'OVERRIDE_FILE_RISK': {
        'scope': {'CL'},
        'pattern': r'\bOVRDBF\b.*?(?:&|\%SST|\%SUBST)',
        'descripcion': 'Override de archivo con parámetros dinámicos. Riesgo de acceso no autorizado a archivos.',
        'categoria': 'Insecure Configuration',
        'cwe': 'CWE-73',
        'owasp': 'A05:2021',
        'criticidad': 'Media',
        'mitigacion': 'Validar nombres de archivo y librería contra lista blanca.',
        'referencias': ['IBM Doc: OVRDBF']
    },
    'HARDCODED_IP_PUBLIC': {
        'scope': {'CL', 'RPG', 'SQL', 'DESCONOCIDO'},
        'pattern': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b(?!.*(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.))',
        'descripcion': 'Dirección IP pública expuesta en el código fuente.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200',
        'owasp': 'A01:2021',
        'criticidad': 'Media',
        'mitigacion': 'Externalizar IPs a tablas de configuración o DNS.',
        'referencias': ['IBM Doc: CFGTCP']
    },
    'MQ_API_USAGE': {
        'scope': {'RPG'},
        'pattern': r'\b(?:MQCONN|MQOPEN|MQGET|MQPUT|MQCLOSE|MQDISC)\b',
        'descripcion': 'Uso de APIs MQ detectado en la rutina. Relevante para auditoría de conectividad y manejo de errores.',
        'categoria': 'Integration Surface / MQ',
        'cwe': 'CWE-668',
        'owasp': 'A05:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Revisar validación de colas, manager y códigos de retorno.',
        'referencias': ['IBM MQ API Docs']
    },
    'BLIND_MONMSG': {
        'scope': {'CL'},
        'pattern': r'MONMSG\s+(?:MSGID\(\))?\s*CPF0000\s*',
        'descripcion': 'Monitoreo ciego con CPF0000. Silencia excepciones, enmascarando ataques o fallos graves.',
        'categoria': 'Insufficient Logging / Monitoring',
        'cwe': 'CWE-391',
        'owasp': 'A09:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Interceptar códigos de error específicos (ej. CPF2105) y registrar la falla.',
        'referencias': ['IBM Doc: MONMSG (https://www.ibm.com/docs/en/i/7.5?topic=messages-monitoring-cl-messages-monmsg)']
    },
    'IP_ADDRESSES': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF', 'DESCONOCIDO'},
        'pattern': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b',
        'descripcion': 'Dirección IP de red privada local expuesta. Otorga vectores informativos para post-explotación.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200',
        'owasp': 'A01:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Abstraer IPs delegando la resolución en la tabla de hosts (CFGTCP) o DNS interno.',
        'referencias': ['IBM Doc: CFGTCP (https://www.ibm.com/docs/en/i/7.5?topic=tcpip-configuring-host-table)']
    },
    'SYSTEM_PATHS_QSYS': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF', 'DESCONOCIDO'},
        'pattern': r'(?:/QSYS\.LIB/|/usr/|/etc/|/var/|/home/)[\w/.-]+',
        'descripcion': 'Rutas físicas absolutas incrustadas del IFS o entorno QSYS.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200',
        'owasp': 'A05:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Externalizar rutas mediante variables de entorno o data areas lógicas.',
        'referencias': ['IBM Doc: IFS Structure (https://www.ibm.com/docs/en/i/7.5?topic=sc-integrated-file-system)']
    },
    'SQL_PROCEDURAL_CHANGE': {
        'scope': {'SQL'},
        'pattern': r'\b(?:UPDATE|INSERT|DELETE|MERGE)\b',
        'descripcion': 'Sentencia SQL de cambio de datos detectada.',
        'categoria': 'SQL Execution / Review',
        'cwe': 'CWE-89',
        'owasp': 'A03:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Confirmar filtros, alcance y consistencia transaccional.',
        'referencias': ['IBM Db2 for i SQL']
    },
    'CL_SENSITIVE_COMMANDS': {
        'scope': {'CL'},
        'pattern': r'\b(?:DSPLIB|DSPJOB|WRKOBJ|WRKSPLF|DSPFD|DSPOBJD|WRKACTJOB|WRKSBSD)\b',
        'descripcion': 'Comandos CL de visualización/trabajo que pueden exponer información sensible del sistema.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200',
        'owasp': 'A01:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Restringir acceso a comandos de visualización a perfiles administrativos. Evitar en código productivo.',
        'referencias': ['IBM Doc: Display Commands']
    },
    'DATA_AREA_MODIFICATION': {
        'scope': {'CL'},
        'pattern': r'\bCHGDTAARA\b',
        'descripcion': 'Modificación de Data Area. Puede alterar configuración global del sistema.',
        'categoria': 'Configuration Change',
        'cwe': 'CWE-284',
        'owasp': 'A05:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Auditar cambios de Data Areas. Restringir autoridad de modificación.',
        'referencias': ['IBM Doc: CHGDTAARA']
    },
    'GOTO_ANTI_PATTERN': {
        'scope': {'CL'},
        'pattern': r'\bGOTO\s+CMDLBL\b',
        'descripcion': 'Uso de GOTO en CL. Anti-patrón de control de flujo que dificulta mantenimiento y auditoría.',
        'categoria': 'Code Quality / Maintainability',
        'cwe': 'CWE-1044',
        'owasp': 'A05:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Preferir estructuras DO/ENDDO, IF/ELSE sobre GOTO. Mejora legibilidad y mantenibilidad.',
        'referencias': ['IBM Doc: GOTO']
    },
    'HARDCODED_LIBRARY_NAMES': {
        'scope': {'CL', 'RPG', 'SQL', 'DESCONOCIDO'},
        'pattern': r'\b(?:QTEMP|QGPL|QSYS|QUSRSYS|QSYS2)\b/[A-Z0-9]{1,10}\b',
        'descripcion': 'Referencia a objeto en biblioteca del sistema hardcodeada. Puede revelar arquitectura interna.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-200',
        'owasp': 'A05:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Usar variables o data areas para calificar bibliotecas. Facilita portabilidad entre ambientes.',
        'referencias': ['IBM Doc: System Libraries']
    },
    'CL_SENSITIVE_COMMANDS': {  # ← NUEVA REGLA
    'scope': {'CL'},
    'pattern': r'\b(?:DSPLIB|DSPJOB|WRKOBJ|WRKSPLF|DSPFD|DSPOBJD|WRKACTJOB|WRKSBSD)\b',
    'descripcion': 'Comandos CL de visualización/trabajo que pueden exponer información sensible del sistema.',
    'categoria': 'Information Disclosure',
    'cwe': 'CWE-200',
    'owasp': 'A01:2021',
    'criticidad': 'Baja',
    'mitigacion': 'Restringir acceso a comandos de visualización a perfiles administrativos. Evitar en código productivo.',
    'referencias': ['IBM Doc: Display Commands']
    }
}

RULES_MOTOR_B_PATTERNS = {
    'SENSITIVE_COMMENT_LEAK': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF', 'DESCONOCIDO'},
        'pattern': r'\b(?:password|passwd|pwd|token|secret|api[_-]?key|credencial|clave|usuario|usr|bearer|authorization|private key|client secret)\b',
        'descripcion': 'Comentario con posible fuga de información sensible.',
        'categoria': 'Information Leakage',
        'cwe': 'CWE-615',
        'owasp': 'A01:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Limpiar comentarios sensibles y notas internas de desarrollo.',
        'referencias': ['CWE-615']
    },
    # NUEVA: Detecta TODO/FIXME/HACK con credenciales (id 1005 del JSON)
    'TODO_FIXME_SENSITIVE': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF', 'DESCONOCIDO'},
        'pattern': r'(?:TODO|FIXME|HACK|XXX|BUG|TEMP|TEMPORAL).*?(?:PASSWORD|USER|ADMIN|SECRET|KEY|TOKEN|CREDENCIAL|CLAVE)',
        'descripcion': 'Marcador TODO/FIXME/HACK que menciona credenciales o información sensible. Deuda técnica crítica.',
        'categoria': 'Information Disclosure / Technical Debt',
        'cwe': 'CWE-532',
        'owasp': 'A09:2021',
        'criticidad': 'Media',
        'mitigacion': 'Resolver marcadores TODO/FIXME antes de producción. Nunca dejar credenciales en comentarios.',
        'referencias': ['CWE-532 (https://cwe.mitre.org/data/definitions/532.html)']
    },
    # NUEVA: Comentarios con IPs o rutas
    'COMMENT_IP_OR_PATH': {
        'scope': {'CL', 'RPG', 'SQL', 'PF', 'DSPF', 'DESCONOCIDO'},
        'pattern': r'(?:TODO|FIXME|HACK|XXX|NOTE|PENDIENTE).*?(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|/QSYS|/usr/|/home/)',
        'descripcion': 'Comentario con marcador que incluye IPs o rutas del sistema.',
        'categoria': 'Information Disclosure',
        'cwe': 'CWE-615',
        'owasp': 'A01:2021',
        'criticidad': 'Baja',
        'mitigacion': 'Eliminar información sensible de comentarios. Usar referencias abstractas.',
        'referencias': ['CWE-615']
    }
}
INFO_RULES_PATTERNS = {
    'GENERIC_CALLS': {
        'scope': {'CL'},
        'pattern': r'\bCALL\s+(?:PGM\s*\(\s*)?([\w$#@./&]+)',
        'descripcion': 'Llamada a programa externo. Mapeado para auditoría de flujo lógico y dependencias.',
        'categoria': 'Reconnaissance / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Verificar que el programa llamado valide correctamente los parámetros recibidos.',
        'referencias': ['IBM Doc: CALL']
    },
    
    # AJUSTADO: Ahora detecta CPYF con continuaciones de línea (+)
    'CPYF_OPERATIONS': {
        'scope': {'CL'},
        'pattern': r'\bCPYF\b.*?(?:FROMFILE|TOFILE)\s*\(\s*([\w$#@./&]+)\s*\)',
        'descripcion': 'Operación de copia de archivos físicos. Mapea flujo de datos entre archivos.',
        'categoria': 'Data Flow / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar origen y destino de las copias. Validar que los archivos existan.',
        'referencias': ['IBM Doc: CPYF']
    },
    
    # AJUSTADO: Simplificado para detectar OVRDBF más fácilmente
    'OVRDBF_USAGE': {
        'scope': {'CL'},
        'pattern': r'\bOVRDBF\b.*?FILE\s*\(\s*([\w$#@./&]+)\s*\)',
        'descripcion': 'Override de archivo de base de datos. Mapea redirecciones de archivos en runtime.',
        'categoria': 'Configuration / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Asegurar que los overrides se liberen correctamente con DLTOVR. Documentar redirecciones.',
        'referencias': ['IBM Doc: OVRDBF']
    },
    
    'SBMJOB_BATCH_CALLS': {
        'scope': {'CL'},
        'pattern': r'\bSBMJOB\b\s+CMD\(\s*CALL\s+PGM\(\s*([\w$#@./&]+)\s*\)',
        'descripcion': 'Submit de job batch que ejecuta un programa. Mapea dependencias de procesamiento asincrónico.',
        'categoria': 'Batch Processing / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar jobs batch y sus dependencias. Monitorear ejecución en colas.',
        'referencias': ['IBM Doc: SBMJOB']
    },
    
    # AJUSTADO: Detecta tanto RTVDTAARA como CHGDTAARA con DTAARA
    'DATA_AREA_ACCESS': {
        'scope': {'CL'},
        'pattern': r'\b(?:RTVDTAARA|CHGDTAARA)\b.*?DTAARA\s*\(\s*([\w$#@./&]+)\s*\)',
        'descripcion': 'Acceso a Data Area (lectura/escritura). Mapea configuración compartida entre programas.',
        'categoria': 'Shared Configuration / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar propósito de cada Data Area. Restringir autoridad de modificación.',
        'referencias': ['IBM Doc: Data Areas']
    },
    
    # AJUSTADO: Detecta tanto QSYS/NOMBRE como qsys2.nombre (punto o slash)
    'HARDCODED_LIBRARY_NAMES': {
        'scope': {'CL', 'RPG', 'SQL', 'DESCONOCIDO'},
        'pattern': r'\b(?:QTEMP|QGPL|QSYS|QUSRSYS|QSYS2)[/.]([\w$#@]+)',
        'descripcion': 'Referencia a objeto en biblioteca del sistema hardcodeada. Revela arquitectura interna.',
        'categoria': 'System Architecture / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Usar variables o data areas para calificar bibliotecas. Facilita portabilidad entre ambientes.',
        'referencias': ['IBM Doc: System Libraries']
    },
    
    'SENSITIVE_API_USAGE': {
        'scope': {'CL', 'RPG'},
        'pattern': r'\b(?:QCMDEXC|QUSCRTUS|QUSCHGUS|QUSRTVUS|QMHSNDPM|QMHRMVPM|QSYRUSRI|QSYCHGPW|QSYLVLUS)\b',
        'descripcion': 'Uso de API del sistema sensible. Mapea superficie de ataque y dependencias de bajo nivel.',
        'categoria': 'System API / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar propósito de cada API. Validar parámetros de entrada estrictamente.',
        'referencias': ['IBM Doc: System APIs']
    },
    
    'EXTERNAL_FILE_ACCESS': {
        'scope': {'CL', 'RPG', 'SQL', 'DESCONOCIDO'},
        'pattern': r'(?:/QSYS\.LIB/|/usr/|/etc/|/var/|/home/)([\w/.-]+)',
        'descripcion': 'Acceso a archivo en IFS (Integrated File System). Mapea interacción con sistema de archivos.',
        'categoria': 'File System / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Validar permisos de archivos. Externalizar rutas mediante variables de entorno.',
        'referencias': ['IBM Doc: IFS Structure']
    },
    
    'SYSTEM_VALUE_ACCESS': {
        'scope': {'CL'},
        'pattern': r'\b(?:RTVSYSVAL|CHGSYSVAL)\b.*?SYSVAL\s*\(\s*(\w+)\s*\)',
        'descripcion': 'Acceso a Valor del Sistema (System Value). Mapea configuración del sistema.',
        'categoria': 'System Configuration / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar qué valores del sistema se leen/modifican. Restringir cambios a perfiles administrativos.',
        'referencias': ['IBM Doc: System Values']
    },
    
    # AJUSTADO: Detecta construcción dinámica en RPG con variables
    'DYNAMIC_COMMAND_BUILD': {
        'scope': {'CL', 'RPG'},
        'pattern': r'(?:command|cmd|&CMD|&COMANDO)\s*(?:=|\+|\|\|)\s*[\'"]?(?:CALL|SBMJOB|RUNSQL|CHG|CRT|DLT|WRK|DSP|CPYF|OVRDBF|CHKOBJ)',
        'descripcion': 'Construcción dinámica de comando CL mediante concatenación. Mapea comandos generados en runtime.',
        'categoria': 'Dynamic Execution / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar comandos dinámicos. Validar estrictamente todos los componentes antes de construir.',
        'referencias': ['IBM Doc: CL Commands']
    },
    
    'HARDCODED_USER_PROFILES': {
        'scope': {'CL', 'RPG', 'SQL', 'DESCONOCIDO'},
        'pattern': r'\b(?:USRPRF|USER)\s*\(\s*([A-Z][A-Z0-9]{0,9})\s*\)',
        'descripcion': 'Perfil de usuario hardcodeado en comando. Mapea identidades utilizadas por el programa.',
        'categoria': 'Identity / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Externalizar perfiles de usuario a configuración. Evitar hardcodeo de identidades.',
        'referencias': ['IBM Doc: User Profiles']
    },
    
    'JOB_DESCRIPTION_USAGE': {
        'scope': {'CL'},
        'pattern': r'\b(?:JOBD|JOB)\s*\(\s*([\w$#@./&]+)\s*\)',
        'descripcion': 'Referencia a Job Description. Mapea configuraciones de job utilizadas.',
        'categoria': 'Job Configuration / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar job descriptions utilizadas. Validar que existan en el sistema destino.',
        'referencias': ['IBM Doc: Job Descriptions']
    },
    
    'MESSAGE_QUEUE_USAGE': {
        'scope': {'CL'},
        'pattern': r'\b(?:SNDMSG|RCVMSG|SNDPGMMSG|SNDUSRMSG)\b.*?(?:MSGQ|MSGID|MSGDTA|MSGF)\s*\(',
        'descripcion': 'Uso de colas de mensajes. Mapea sistema de notificaciones y alertas.',
        'categoria': 'Messaging / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar mensajes enviados. Validar que las colas de mensajes existan.',
        'referencias': ['IBM Doc: Message Handling']
    },
    
    # NUEVA: Detecta SQL embebido en RPG
    'EMBEDDED_SQL_RPG': {
        'scope': {'RPG'},
        'pattern': r'\bexec\s+sql\b',
        'descripcion': 'SQL embebido en RPG. Mapea interacción con base de datos desde código RPG.',
        'categoria': 'Database Access / Map',
        'criticidad': 'Baja',
        'mitigacion': 'Documentar sentencias SQL embebidas. Validar parámetros y filtros.',
        'referencias': ['IBM Doc: Embedded SQL']
    },
    
    # NUEVA: Detecta uso de cursores SQL
    'SQL_CURSOR_USAGE': {
    'scope': {'RPG', 'SQL'},
    # Detecta DECLARE cursor, OPEN/FETCH/CLOSE seguido de nombre de cursor (no archivo)
    # Excluye casos donde open/close es sobre archivos físicos (dcl-F)
    'pattern': r'\b(?:DECLARE\s+\w+\s+(?:INSENSITIVE\s+)?CURSOR|exec\s+sql\s+(?:open|fetch|close)\s+\w+)',
    'descripcion': 'Uso de cursores SQL. Mapea operaciones de lectura/escritura en base de datos.',
    'categoria': 'Database Access / Map',
    'criticidad': 'Baja',
    'mitigacion': 'Documentar cursores y su propósito. Asegurar cierre correcto de cursores.',
    'referencias': ['IBM Doc: SQL Cursors']
    }
}

# ============================================================================
# FUNCIONES DE COMPILACIÓN Y CACHE
# ============================================================================

_compiled_rules_cache = {}

def get_compiled_rules():
    """Compila los patrones regex bajo demanda y los cachea."""
    try:
        if not _compiled_rules_cache:
            _compiled_rules_cache['motor_a'] = {
                k: {**v, 'pattern': re.compile(v['pattern'], re.IGNORECASE)}
                for k, v in RULES_MOTOR_A_PATTERNS.items()
            }
            _compiled_rules_cache['motor_b'] = {
                k: {**v, 'pattern': re.compile(v['pattern'], re.IGNORECASE)}
                for k, v in RULES_MOTOR_B_PATTERNS.items()
            }
            _compiled_rules_cache['info'] = {
                k: {**v, 'pattern': re.compile(v['pattern'], re.IGNORECASE)}
                for k, v in INFO_RULES_PATTERNS.items()
            }
        return _compiled_rules_cache
    except Exception as e:
        logger.error(f"Error compilando reglas: {e}")
        return {'motor_a': {}, 'motor_b': {}, 'info': {}}

# ============================================================================
# FUNCIONES DE UTILIDAD CON MANEJO DE ERRORES
# ============================================================================

def sha256_file(path):
    """Calcula SHA-256 de un archivo con manejo de errores."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning(f"Error calculando SHA-256 de {path}: {e}")
        return "ERROR_HASH"

def detect_encoding(path):
    """Detecta encoding de un archivo con fallback."""
    if not CHARDET_OK:
        return 'latin-1', 0.0
    try:
        raw = Path(path).read_bytes()[:50000]
        if not raw:
            return 'utf-8', 0.0
        res = chardet.detect(raw)
        enc = res.get('encoding') or 'latin-1'
        conf = float(res.get('confidence', 0.0) or 0.0)
        if conf < 0.70:
            return 'latin-1', conf
        return enc, conf
    except Exception as e:
        logger.warning(f"Error detectando encoding de {path}: {e}")
        return 'latin-1', 0.0

def read_lines(path):
    """Generador que lee líneas una por una con manejo robusto de errores."""
    enc, conf = detect_encoding(path)
    candidates = [enc, 'utf-8', 'cp1252', 'latin-1']
    candidates = list(dict.fromkeys(candidates))  # Eliminar duplicados
    
    for candidate in candidates:
        try:
            with open(path, 'r', encoding=candidate, errors='strict') as f:
                for line in f:
                    yield line, candidate, conf
                return
        except (UnicodeDecodeError, LookupError):
            continue
        except Exception as e:
            logger.warning(f"Error leyendo {path} con {candidate}: {e}")
            continue
    
    # Fallback final con reemplazo de caracteres
    try:
        with open(path, 'r', encoding='latin-1', errors='replace') as f:
            for line in f:
                yield line, 'latin-1', conf
    except Exception as e:
        logger.error(f"Error crítico leyendo {path}: {e}")
        yield "", 'latin-1', 0.0

def is_processable(path):
    """Verifica si un archivo es procesable."""
    try:
        p = Path(path)
        if not p.is_file():
            return False
        if p.suffix.lower() in TEXT_EXTENSIONS:
            return True
        return b'\x00' not in p.read_bytes()[:2048]
    except Exception as e:
        logger.warning(f"Error verificando {path}: {e}")
        return False

def collect_files(folder):
    """Recopila archivos procesables de una carpeta."""
    out = []
    try:
        for root, _, files in os.walk(folder):
            for name in files:
                full = os.path.join(root, name)
                if is_processable(full):
                    out.append(full)
    except Exception as e:
        logger.error(f"Error recorriendo carpeta {folder}: {e}")
    return sorted(out)

# ============================================================================
# FUNCIONES DE CLASIFICACIÓN Y EXPLICACIÓN MEJORADAS
# ============================================================================

def strip_inline_block_comments(line, state):
    """Elimina comentarios de bloque /* */ de una línea CL."""
    result = ''
    i = 0
    try:
        while i < len(line):
            if state['cl_block']:
                end = line.find('*/', i)
                if end == -1:
                    return result, True
                state['cl_block'] = False
                i = end + 2
                continue
            
            start = line.find('/*', i)
            if start == -1:
                result += line[i:]
                break
            
            result += line[i:start]
            end = line.find('*/', start + 2)
            if end == -1:
                state['cl_block'] = True
                break
            i = end + 2
    except Exception as e:
        logger.debug(f"Error procesando comentarios en línea: {e}")
    return result, state['cl_block']

def detect_syntax(lines_iter, file_name):
    """Detecta sintaxis consumiendo solo las primeras 250 líneas del iterador."""
    try:
        ext = Path(file_name).suffix.lower()
        
        sample = []
        for i, (line, _, _) in enumerate(lines_iter):
            if i >= 250:
                break
            sample.append(line.rstrip('\n'))
        
        stripped = [ln.strip() for ln in sample if ln.strip()]
        upper = [ln.upper() for ln in stripped]
        
        score = Counter({'CL': 0, 'RPG': 0, 'SQL': 0, 'PF': 0, 'DSPF': 0})
        
        if ext in {'.cl', '.clp'}:
            score['CL'] += 8
        if ext in {'.rpg', '.rpgle', '.sqlrpgle'}:
            score['RPG'] += 8
        if ext in {'.sql'}:
            score['SQL'] += 8
        if ext in {'.pf', '.lf'}:
            score['PF'] += 8
        if ext in {'.dspf'}:
            score['DSPF'] += 8
        
        for ln in upper:
            if ln.startswith('--'):
                score['SQL'] += 3
            if any(tok in ln for tok in ['QSYS2.', 'FETCH FIRST', 'DECLARE ', 'BEGIN', 'END IF', 'ORDER BY', 'CURRENT_TIMESTAMP', 'SYSTEM_TABLE_SCHEMA', 'SYSTEM_SCHEMA_NAME']):
                score['SQL'] += 3
            if any(tok in ln for tok in ['CTL-OPT', 'DCL-F', 'DCL-S', 'DCL-DS', 'DCL-PI', 'DCL-PR', 'DCL-PROC', 'END-PROC', '/IF DEFINED(*CRTBNDRPG)', 'LIKEDS', 'QUALIFIED', 'USAGE(*INPUT)', 'USAGE(*OUTPUT)']):
                score['RPG'] += 4
            if 'EXEC SQL' in ln:
                score['RPG'] += 5
            if '/IF DEFINED' in ln or '/ENDIF' in ln:
                score['RPG'] += 6
            if re.match(r'^\s*PGM\b', ln):
                score['CL'] += 5
            if any(re.match(r'^\s*' + cmd + r'\b', ln) for cmd in ['DCL', 'DCLF', 'CHGVAR', 'CALL', 'MONMSG', 'RTVJOBA', 'RTVDTAARA', 'OVRDBF', 'DLYJOB', 'CHKOBJ', 'ENDPGM']):
                score['CL'] += 3
            if re.match(r'^\s*R\s+\w+', ln) or re.match(r'^\s*K\s+\w+', ln):
                score['PF'] += 4
            if re.match(r'^\s*\w+\s+\d+\s+[APSBFLTZHGO]\b', ln):
                score['PF'] += 4
        
        sql_heavy = sum(1 for ln in upper if any(tok in ln for tok in SQL_TOKENS))
        rpg_heavy = sum(1 for ln in upper if any(tok in ln for tok in RPG_TOKENS))
        cl_heavy = sum(1 for ln in upper if any(re.match(r'^\s*' + cmd + r'\b', ln) for cmd in ['PGM', 'DCL', 'DCLF', 'CHGVAR', 'CALL', 'MONMSG', 'RUNSQL', 'RUNSQLSTM', 'RTVJOBA', 'ENDPGM']))
        
        if sql_heavy >= 6 and rpg_heavy <= 2 and cl_heavy <= 2:
            score['SQL'] += 20
        if rpg_heavy >= 6:
            score['RPG'] += 20
        if cl_heavy >= 6:
            score['CL'] += 20
        
        best_score = max(score.values())
        if best_score == 0:
            return 'DESCONOCIDO'
        
        candidates = [k for k, v in score.items() if v == best_score]
        if len(candidates) > 1:
            ext_priority = {
                '.cl': 'CL', '.clp': 'CL',
                '.rpg': 'RPG', '.rpgle': 'RPG', '.sqlrpgle': 'RPG',
                '.sql': 'SQL',
                '.pf': 'PF', '.lf': 'PF',
                '.dspf': 'DSPF'
            }
            if ext in ext_priority and ext_priority[ext] in candidates:
                return ext_priority[ext]
            return sorted(candidates)[0]
        
        return candidates[0]
    except Exception as e:
        logger.error(f"Error detectando sintaxis de {file_name}: {e}")
        return 'DESCONOCIDO'

def explain_cl(raw):
    """Explica una línea de código CL con detección mejorada de etiquetas y parámetros."""
    try:
        s = raw.strip().upper()
        
        # Detectar etiquetas (labels) de CL
        if re.match(r'^[A-Z0-9_]+:\s*$', s):
            return f'[LABEL] Etiqueta de control de flujo: {s.rstrip(":")}'
        
        # Detectar continuaciones de comando (líneas que inician con espacios y tienen parámetros)
        if raw.startswith(' ') or raw.startswith('\t'):
            # Es una continuación de línea con +
            if raw.rstrip().endswith('+'):
                return '[CONTINUATION] Continuación de comando CL (parámetros adicionales).'
            # Parámetros comunes de comandos CL
            first_word = s.split()[0] if s.split() else ''
            if first_word in CL_PARAMS:
                return f'[PARAM] Parámetro de comando CL: {first_word}'
            if re.match(r'^\s*[\'"&]', s) or re.match(r'^\s*\)', s):
                return '[CONTINUATION] Continuación de comando CL (valores o parámetros).'
            return '[CONTINUATION] Continuación de comando CL.'
        
        # Buscar en diccionario de comandos
        for cmd, msg in CL_COMMANDS.items():
            if re.match(r'^' + re.escape(cmd) + r'\b', s):
                return msg
        
        return 'Instrucción u operación estándar nativa.'
    except Exception as e:
        logger.debug(f"Error explicando línea CL: {e}")
        return 'Instrucción u operación estándar nativa.'

def explain_rpg(raw):
    """Explica una línea de código RPG con manejo mejorado de prefijos y continuaciones."""
    try:
        s = raw.strip().upper()
        original_stripped = raw.strip()
        
        # Manejar líneas con prefijos de usuario/fecha (ej: "USR01 2026-01-01 codigo")
        # Intentar extraer el código real si hay un prefijo
        clean_line = s
        # Buscar patrones comunes de prefijos: nombre de usuario, fecha, etc.
        match = re.match(r'^[A-Z0-9]{2,10}\s+\d{4}[-/]\d{2}[-/]\d{2}\s+(.+)$', s)
        if match:
            clean_line = match.group(1)
        else:
            # Si no hay fecha, buscar solo nombre de usuario
            match = re.match(r'^[A-Z0-9]{2,10}\s{2,}(.+)$', s)
            if match and not any(kw in s for kw in ['DCL-', 'CTL-OPT', 'EXEC SQL', 'IF ', 'ELSE', 'ENDIF']):
                clean_line = match.group(1)
        
        # Detectar continuaciones de línea RPG (inician con espacios y no son directivas)
        if (raw.startswith(' ') or raw.startswith('\t')) and not s.startswith('/'):
            # SQL embebido continuado
            if any(kw in clean_line for kw in ['INSERT', 'VALUES', 'FROM', 'WHERE', 'ORDER BY', 'AND', 'OR', 'INTO', 'SELECT', 'SET', 'DECLARE', 'FETCH', 'OPEN', 'CLOSE', 'GET DIAGNOSTICS']):
                return f'[SQL-EMBEDDED] Continuación de sentencia SQL embebida.'
            # Asignaciones a subcampos (ej: msjerr.errcde = -9011)
            if re.match(r'^\s*\w+\.\w+\s*=', clean_line):
                return '[ASSIGNMENT] Asignación de valor a subcampo de estructura de datos.'
            # Asignaciones simples
            if re.match(r'^\s*\w+\s*=', clean_line) and not clean_line.startswith('DCL') and not clean_line.startswith('EXEC'):
                return '[ASSIGNMENT] Asignación de valor a variable o campo.'
            # Llamadas a procedimientos continuadas
            if re.match(r'^\s*\w+\s*\(', clean_line) or re.match(r'^\s*:', clean_line):
                return '[CALL-CONT] Continuación de llamada a procedimiento o función.'
            # Parámetros de procedimiento
            if re.match(r'^\s*\w+\s+(?:CHAR|INT|PACKED|ZONED|VARCHAR|DATE|TIMESTAMP|POINTER|LIKEDS|LIKEREC)\b', clean_line):
                return '[PARAM-DEF] Definición de parámetro de procedimiento.'
            # Keywords de campo en DS
            if re.match(r'^\s*\w+\s+\w+\(', clean_line) and any(kw in clean_line for kw in ['POS(', 'OVERLAY(', 'DIM(', 'INZ(', 'CONST', 'OPTIONS(', 'VALUE']):
                return '[DS-FIELD] Definición de subcampo en estructura de datos.'
            # Constantes MQ o valores especiales
            if re.match(r'^\s*(?:GMWT|GMFIQ|GMCONV|GMATM|OOINPQ|OOFIQ|CONONE|CCOK|CCFAIL|RCNONE|RC2033|RC2079|MINONE|CINONE)\b', clean_line):
                return '[CONSTANT] Constante de API (MQ o sistema).'
            # Continuación general
            if clean_line.startswith('+') or clean_line.startswith(':') or clean_line.startswith(')') or clean_line.startswith('('):
                return '[CONTINUATION] Continuación de expresión RPG.'
            # Si la línea tiene operadores de concatenación o aritméticos
            if any(op in clean_line for op in ['+', '-', '*', '/', '>', '<', '=', '<>', '>=', '<=']):
                return '[EXPRESSION] Expresión o continuación de cálculo RPG.'
            return '[CONTINUATION] Continuación de línea RPG.'
        
        # Mapeo de tokens RPG (ordenado por longitud para evitar matches parciales)
        mapping = [
            # Directivas y opciones
            ('CTL-OPT', '[CTL-OPT] Opciones de compilación o ejecución RPG.'),
            ('SET OPTION', '[SET OPTION] Configura opciones de compilación SQL embebido.'),
            # Declaraciones free-form
            ('DCL-F', '[DCL-F] Declara archivo en RPG free-form.'),
            ('DCL-S', '[DCL-S] Declara variable escalar.'),
            ('DCL-DS', '[DCL-DS] Declara estructura de datos.'),
            ('DCL-PI', '[DCL-PI] Declara interfaz de procedimiento.'),
            ('DCL-PR', '[DCL-PR] Declara prototipo de procedimiento.'),
            ('DCL-PROC', '[DCL-PROC] Inicio de procedimiento.'),
            ('END-DS', '[END-DS] Fin de estructura de datos.'),
            ('END-PR', '[END-PR] Fin de prototipo de procedimiento.'),
            ('END-PI', '[END-PI] Fin de interfaz de procedimiento.'),
            ('END-PROC', '[END-PROC] Fin de procedimiento.'),
            # SQL embebido
            ('EXEC SQL', '[EXEC SQL] Sentencia SQL embebida en RPG.'),
            # Control de flujo
            ('IF ', '[IF] Control condicional RPG.'),
            ('ELSE', '[ELSE] Rama alternativa de control RPG.'),
            ('ENDIF', '[ENDIF] Fin de condicional RPG.'),
            ('SELECT', '[SELECT] Inicio de bloque condicional múltiple.'),
            ('WHEN ', '[WHEN] Rama condicional dentro de SELECT.'),
            ('OTHER', '[OTHER] Rama por defecto en SELECT.'),
            ('ENDSL', '[ENDSL] Fin de bloque SELECT.'),
            ('DOW ', '[DOW] Inicio de bucle DO-WHILE.'),
            ('DOU ', '[DOU] Inicio de bucle DO-UNTIL.'),
            ('ENDDO', '[ENDDO] Fin de bloque DO.'),
            ('FOR ', '[FOR] Inicio de bucle FOR.'),
            ('ENDFOR', '[ENDFOR] Fin de bucle FOR.'),
            ('ITER', '[ITER] Salta a siguiente iteración del bucle.'),
            ('LEAVE', '[LEAVE] Sale del bucle actual.'),
            ('RETURN', '[RETURN] Retorna desde programa o procedimiento.'),
            # Operaciones de archivo
            ('CHAIN', '[CHAIN] Recupera registro por clave.'),
            ('SETLL', '[SETLL] Posiciona puntero al inicio de clave.'),
            ('READE', '[READE] Lee siguiente registro igual.'),
            ('READ', '[READ] Lee siguiente registro.'),
            ('WRITE', '[WRITE] Escribe registro.'),
            ('UPDATE', '[UPDATE] Actualiza registro.'),
            ('DELETE', '[DELETE] Elimina registro.'),
            ('OPEN', '[OPEN] Abre archivo.'),
            ('CLOSE', '[CLOSE] Cierra archivo.'),
            # Llamadas
            ('CALLP', '[CALLP] Invoca procedimiento.'),
            ('EXSR', '[EXSR] Ejecuta subrutina.'),
            ('BEGSR', '[BEGSR] Inicio de subrutina.'),
            ('ENDSR', '[ENDSR] Fin de subrutina.'),
            # Inicialización y reset
            ('CLEAR ', '[CLEAR] Inicializa variable a valores por defecto.'),
            ('RESET ', '[RESET] Reinicia variable o estructura de datos.'),
            # Copybooks legacy
            ('D/COPY', '[D/COPY] Copia miembro de definición (copybook).'),
            ('I/COPY', '[I/COPY] Copia miembro de inclusión (copybook).'),
            ('H/COPY', '[H/COPY] Copia miembro de cabecera (copybook).'),
            ('C/COPY', '[C/COPY] Copia miembro de cálculo (copybook).'),
            ('F/COPY', '[F/COPY] Copia miembro de archivo (copybook).'),
            ('O/COPY', '[O/COPY] Copia miembro de salida (copybook).'),
            # Indicadores
            ('*INLR', '[*INLR] Indicador de último registro del programa.'),
            ('*IN', '[*IN] Referencia a indicador.'),
            # BIFs (Built-in Functions) - muy comunes como inicio de expresión
            ('%TRIM', '[BIF %TRIM] Función integrada: elimina espacios en blanco.'),
            ('%TRIMR', '[BIF %TRIMR] Función integrada: elimina espacios a la derecha.'),
            ('%TRIML', '[BIF %TRIML] Función integrada: elimina espacios a la izquierda.'),
            ('%CHAR', '[BIF %CHAR] Función integrada: convierte a carácter.'),
            ('%SUBST', '[BIF %SUBST] Función integrada: extrae subcadena.'),
            ('%DATE', '[BIF %DATE] Función integrada: convierte a fecha.'),
            ('%TIME', '[BIF %TIME] Función integrada: convierte a hora.'),
            ('%TIMESTAMP', '[BIF %TIMESTAMP] Función integrada: marca de tiempo actual.'),
            ('%EDITC', '[BIF %EDITC] Función integrada: edición con código.'),
            ('%EDITW', '[BIF %EDITW] Función integrada: edición con máscara.'),
            ('%LOOKUP', '[BIF %LOOKUP] Función integrada: busca en array o tabla.'),
            ('%FOUND', '[BIF %FOUND] Función integrada: verifica si se encontró registro.'),
            ('%ERROR', '[BIF %ERROR] Función integrada: verifica si hubo error.'),
            ('%PARMS', '[BIF %PARMS] Función integrada: cuenta parámetros recibidos.'),
            ('%SIZE', '[BIF %SIZE] Función integrada: tamaño de variable.'),
            ('%ADDR', '[BIF %ADDR] Función integrada: dirección de memoria.'),
            ('%LEN', '[BIF %LEN] Función integrada: longitud de variable.'),
            ('%CHECK', '[BIF %CHECK] Función integrada: verifica caracteres.'),
            ('%LIST', '[BIF %LIST] Función integrada: lista de valores.'),
            ('%DEC', '[BIF %DEC] Función integrada: convierte a decimal.'),
            ('%INT', '[BIF %INT] Función integrada: convierte a entero.'),
            ('%REALLOC', '[BIF %REALLOC] Función integrada: reasigna memoria.'),
            # APIs de conversión
            ('CVTHC', '[CVTHC] API: convierte caracteres a hex.'),
            ('CVTCH', '[CVTCH] API: convierte hex a caracteres.'),
            # Legacy RPG (columnas fijas)
            ('D ', '[D-SPEC] Especificación de definición (legacy).'),
            ('C ', '[C-SPEC] Especificación de cálculo (legacy).'),
            ('F ', '[F-SPEC] Especificación de archivo (legacy).'),
            ('H ', '[H-SPEC] Especificación de cabecera (legacy).'),
            ('I ', '[I-SPEC] Especificación de entrada (legacy).'),
            ('O ', '[O-SPEC] Especificación de salida (legacy).'),
            ('P ', '[P-SPEC] Especificación de procedimiento (legacy).'),
        ]
        
        for key, msg in mapping:
            if clean_line.startswith(key) or key in clean_line:
                return msg
        
        # Detectar asignaciones (variable = valor)
        if re.match(r'^\w+\s*=', clean_line) and not clean_line.startswith('DCL') and not clean_line.startswith('EXEC'):
            return '[ASSIGNMENT] Asignación de valor a variable.'
        
        # Detectar llamadas a procedimiento (nombre_proc(...))
        if re.match(r'^\w+\s*\(', clean_line):
            proc_name = clean_line.split("(")[0].strip()
            return f'[CALL] Llamada a procedimiento: {proc_name}'
        
        # Detectar definiciones de campo en DS (nombre tipo(dim))
        if re.match(r'^\w+\s+(?:CHAR|INT|PACKED|ZONED|VARCHAR|DATE|TIMESTAMP|POINTER|IND)\s*\(', clean_line):
            return '[DS-FIELD] Definición de subcampo en estructura de datos.'
        
        # Detectar keywords de DS
        if any(kw in clean_line for kw in ['EXTNAME(', 'QUALIFIED', 'TEMPLATE', 'LIKEDS(', 'LIKEREC(', 'BASED(', 'OVERLAY(', 'POS(', 'DIM(', 'INZ(', 'CONST', 'OPTIONS(']):
            return '[DS-KEYWORD] Keyword de estructura de datos o parámetro.'
        
        # Si la línea limpia tiene contenido pero no se reconoció, intentar con la original
        if clean_line != s:
            for key, msg in mapping:
                if s.startswith(key) or key in s:
                    return msg
        
        return 'Instrucción u operación estándar nativa.'
    except Exception as e:
        logger.debug(f"Error explicando línea RPG: {e}")
        return 'Instrucción u operación estándar nativa.'

def explain_sql(raw):
    """Explica una línea de código SQL con detección mejorada de cláusulas."""
    try:
        s = raw.strip().upper()
        mapping = [
            ('BEGIN', '[BEGIN] Inicio de bloque procedural SQL.'),
            ('DECLARE', '[DECLARE] Declaración de variable o cursor SQL.'),
            ('SELECT', '[SELECT] Consulta SQL.'),
            ('UPDATE', '[UPDATE] Actualización SQL.'),
            ('INSERT INTO', '[INSERT INTO] Inserción de registros.'),
            ('INSERT', '[INSERT] Inserción SQL.'),
            ('DELETE', '[DELETE] Eliminación SQL.'),
            ('MERGE', '[MERGE] Operación combinada SQL.'),
            ('VALUES', '[VALUES] Valores para inserción SQL.'),
            ('INTO ', '[INTO] Destino de datos seleccionados.'),
            ('FROM ', '[FROM] Tabla origen de consulta.'),
            ('WHERE', '[WHERE] Filtro condicional SQL.'),
            ('AND ', '[AND] Operador lógico AND en condición SQL.'),
            ('OR ', '[OR] Operador lógico OR en condición SQL.'),
            ('ORDER BY', '[ORDER BY] Ordenamiento de resultados.'),
            ('GROUP BY', '[GROUP BY] Agrupamiento de resultados.'),
            ('HAVING', '[HAVING] Filtro de grupo SQL.'),
            ('FETCH FIRST', '[FETCH FIRST] Limita cantidad de filas retornadas.'),
            ('FETCH', '[FETCH] Recupera filas desde cursor.'),
            ('ROWS ONLY', '[ROWS ONLY] Restringe solo a filas (sin actualización).'),
            ('LIKE ', '[LIKE] Comparación de patrón en SQL.'),
            ('IN (', '[IN] Verifica pertenencia a conjunto de valores.'),
            ('BETWEEN', '[BETWEEN] Verifica rango de valores.'),
            ('IS NULL', '[IS NULL] Verifica valor nulo.'),
            ('IS NOT NULL', '[IS NOT NULL] Verifica valor no nulo.'),
            ('JOIN', '[JOIN] Unión de tablas SQL.'),
            ('LEFT JOIN', '[LEFT JOIN] Unión izquierda de tablas.'),
            ('RIGHT JOIN', '[RIGHT JOIN] Unión derecha de tablas.'),
            ('INNER JOIN', '[INNER JOIN] Unión interna de tablas.'),
            ('ON ', '[ON] Condición de unión entre tablas.'),
            ('UNION', '[UNION] Combina resultados de consultas.'),
            ('EXCEPT', '[EXCEPT] Diferencia de conjuntos SQL.'),
            ('INTERSECT', '[INTERSECT] Intersección de conjuntos SQL.'),
            ('CASE', '[CASE] Expresión condicional SQL.'),
            ('WHEN ', '[WHEN] Rama condicional en CASE SQL.'),
            ('THEN', '[THEN] Resultado de condición en CASE SQL.'),
            ('ELSE', '[ELSE] Rama por defecto en CASE SQL.'),
            ('END', '[END] Fin de bloque o expresión CASE SQL.'),
            ('IF ', '[IF] Control condicional procedural SQL.'),
            ('END IF', '[END IF] Fin de condicional procedural SQL.'),
            ('WHILE', '[WHILE] Bucle condicional procedural SQL.'),
            ('END WHILE', '[END WHILE] Fin de bucle procedural SQL.'),
            ('LOOP', '[LOOP] Bucle infinito procedural SQL.'),
            ('END LOOP', '[END LOOP] Fin de bucle procedural SQL.'),
            ('REPEAT', '[REPEAT] Bucle con condición al final.'),
            ('UNTIL', '[UNTIL] Condición de salida de bucle.'),
            ('LEAVE', '[LEAVE] Sale de bloque o bucle SQL.'),
            ('ITERATE', '[ITERATE] Salta a siguiente iteración SQL.'),
            ('RETURN', '[RETURN] Retorna desde rutina SQL.'),
            ('SIGNAL', '[SIGNAL] Genera excepción SQL personalizada.'),
            ('RESIGNAL', '[RESIGNAL] Re-propaga excepción SQL.'),
            ('GET DIAGNOSTICS', '[GET DIAGNOSTICS] Recupera información de diagnóstico SQL.'),
            ('SET OPTION', '[SET OPTION] Opciones de compilación SQL embebido.'),
            ('COMMIT', '[COMMIT] Confirma transacción.'),
            ('ROLLBACK', '[ROLLBACK] Revierte transacción.'),
            ('SAVEPOINT', '[SAVEPOINT] Punto de guardado en transacción.'),
            ('LOCK TABLE', '[LOCK TABLE] Bloquea tabla para acceso exclusivo.'),
            ('CREATE', '[CREATE] Crea objeto de base de datos.'),
            ('ALTER', '[ALTER] Modifica objeto de base de datos.'),
            ('DROP', '[DROP] Elimina objeto de base de datos.'),
            ('GRANT', '[GRANT] Otorga privilegios.'),
            ('REVOKE', '[REVOKE] Revoca privilegios.'),
            ('IDENTITY_VAL_LOCAL', '[IDENTITY_VAL_LOCAL] Recupera último valor de identidad generado.'),
            ('CURRENT TIMESTAMP', '[CURRENT TIMESTAMP] Marca de tiempo actual del sistema.'),
            ('CURRENT DATE', '[CURRENT DATE] Fecha actual del sistema.'),
            ('CURRENT TIME', '[CURRENT TIME] Hora actual del sistema.'),
            ('CURRENT USER', '[CURRENT USER] Usuario actual de la sesión.'),
            ('CAST(', '[CAST] Conversión de tipo de dato.'),
            ('COALESCE(', '[COALESCE] Retorna primer valor no nulo.'),
            ('NULLIF(', '[NULLIF] Retorna nulo si expresiones son iguales.'),
            ('COUNT(', '[COUNT] Función de agregación: cuenta filas.'),
            ('SUM(', '[SUM] Función de agregación: suma valores.'),
            ('AVG(', '[AVG] Función de agregación: promedio.'),
            ('MIN(', '[MIN] Función de agregación: valor mínimo.'),
            ('MAX(', '[MAX] Función de agregación: valor máximo.'),
            ('SUBSTR(', '[SUBSTR] Extrae subcadena.'),
            ('TRIM(', '[TRIM] Elimina espacios en blanco.'),
            ('UPPER(', '[UPPER] Convierte a mayúsculas.'),
            ('LOWER(', '[LOWER] Convierte a minúsculas.'),
            ('LENGTH(', '[LENGTH] Longitud de cadena.'),
            ('REPLACE(', '[REPLACE] Reemplaza subcadena.'),
            ('DECIMAL(', '[DECIMAL] Convierte a decimal.'),
            ('INTEGER(', '[INTEGER] Convierte a entero.'),
            ('CHAR(', '[CHAR] Convierte a carácter.'),
            ('VARCHAR(', '[VARCHAR] Convierte a cadena variable.'),
            ('DATE(', '[DATE] Convierte a fecha.'),
            ('TIME(', '[TIME] Convierte a hora.'),
            ('TIMESTAMP(', '[TIMESTAMP] Convierte a marca de tiempo.'),
        ]
        for key, msg in mapping:
            if s.startswith(key) or key in s:
                return msg
        
        # Detectar cláusulas que inician con espacios (continuaciones SQL)
        if (raw.startswith(' ') or raw.startswith('\t')):
            if re.match(r'^\s*(?:AND|OR|ON|SET|VALUES|INTO|FROM|WHERE|ORDER|GROUP|HAVING|FETCH|ROWS|UNION|EXCEPT|INTERSECT)\b', s):
                return f'[SQL-CLAUSE] Continuación de cláusula SQL: {s.split()[0]}'
            if re.match(r'^\s*(?:a\.|b\.|c\.)\w+', s):
                return '[SQL-COLUMN] Referencia a columna de tabla con alias.'
            return '[SQL-CONT] Continuación de sentencia SQL.'
        
        return 'Instrucción u operación estándar nativa.'
    except Exception as e:
        logger.debug(f"Error explicando línea SQL: {e}")
        return 'Instrucción u operación estándar nativa.'
        
def explain_pf(raw):
    """Explica una línea de archivo físico."""
    try:
        s = raw.strip().upper()
        if s.startswith('R '):
            return '[R] Define formato o registro.'
        if s.startswith('K '):
            return '[K] Define campo clave.'
        if re.match(r'^\w+\s+\d+\s+[APSBFLTZHGO]\b', s):
            return '[FIELD] Define campo de archivo.'
        return 'Instrucción u operación estándar nativa.'
    except Exception as e:
        logger.debug(f"Error explicando línea PF: {e}")
        return 'Instrucción u operación estándar nativa.'

def classify_and_clean_line(raw, syntax, state):
    """Clasifica y limpia una línea de código."""
    try:
        original = raw.rstrip('\n')
        stripped = original.strip()
        
        if not stripped:
            return 'VACIA', original, 'Línea vacía.'
        
        if syntax == 'SQL':
            if stripped.startswith('--'):
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            return 'CODIGO_ACTIVO', original, explain_sql(original)
        
        if syntax == 'RPG':
            if stripped.startswith('//') or stripped.startswith('**'):
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            if len(original) > 6 and original[6] == '*' and not stripped.startswith('/IF') and not stripped.startswith('/ENDIF'):
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            if stripped.upper().startswith(('D/COPY', 'I/COPY', 'H/COPY', 'C/COPY', 'F/COPY', 'O/COPY')):
                return 'COMENTARIO', original, 'Directiva de copia de miembro fuente (copybook).'
            return 'CODIGO_ACTIVO', original, explain_rpg(original)
        
        if syntax == 'CL':
            cleaned, _ = strip_inline_block_comments(original, state)
            if stripped.startswith('/*') and stripped.endswith('*/'):
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            if stripped.startswith('*') or stripped.startswith('//'):
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            if not cleaned.strip():
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            return 'CODIGO_ACTIVO', original, explain_cl(cleaned)
        
        if syntax in {'PF', 'DSPF'}:
            if stripped.startswith('*') or stripped.startswith('/'):
                return 'COMENTARIO', original, 'Línea dedicada a comentario o documentación interna.'
            return 'CODIGO_ACTIVO', original, explain_pf(original)
        
        return 'CODIGO_ACTIVO', original, 'Instrucción u operación estándar nativa.'
    except Exception as e:
        logger.debug(f"Error clasificando línea: {e}")
        return 'CODIGO_ACTIVO', raw.rstrip('\n'), 'Error procesando línea.'

def map_lines(lines_iter, syntax):
    """Mapea líneas desde un iterador, procesando línea por línea."""
    state = {'cl_block': False}
    mapped = []
    
    try:
        for idx, (raw, _, _) in enumerate(lines_iter, 251):
            naturaleza, contenido, explicacion = classify_and_clean_line(raw, syntax, state)
            mapped.append({
                'linea': idx,
                'contenido': contenido,
                'naturaleza': naturaleza,
                'explicacion_tecnica': explicacion
            })
    except Exception as e:
        logger.error(f"Error mapeando líneas: {e}")
    
    return mapped

def build_finding(file_name, line_no, rid, info, raw):
    """Construye un hallazgo."""
    try:
        return {
            'archivo': file_name,
            'linea': line_no,
            'regla': rid,
            'criticidad': info['criticidad'],
            'categoria': info['categoria'],
            'descripcion': info['descripcion'],
            'codigo_afectado': raw.strip(),
            'match_formateado': f'[{rid}] -> {raw.strip()}',
            'mitigacion': info['mitigacion'],
            'cwe': info.get('cwe', 'N/A'),
            'owasp': info.get('owasp', 'N/A'),
            'referencias': info.get('referencias', [])
        }
    except Exception as e:
        logger.error(f"Error construyendo hallazgo: {e}")
        return None

def apply_rules(mapped, file_name, syntax):
    """Aplica las reglas de seguridad al mapeo de líneas."""
    try:
        rules = get_compiled_rules()
        motor_a, motor_b, info_hits = [], [], []
        seen_mq = False
        
        for item in mapped:
            raw = item['contenido']
            natur = item['naturaleza']
            
            if natur == 'COMENTARIO':
                for rid, info in rules['motor_b'].items():
                    if syntax not in info['scope']:
                        continue
                    try:
                        if info['pattern'].search(raw):
                            finding = build_finding(file_name, item['linea'], rid, info, raw)
                            if finding:
                                motor_b.append(finding)
                    except Exception as e:
                        logger.debug(f"Error aplicando regla {rid}: {e}")
            
            elif natur == 'CODIGO_ACTIVO':
                for rid, info in rules['info'].items():
                    if syntax in info['scope']:
                        try:
                            if info['pattern'].search(raw):
                                finding = build_finding(file_name, item['linea'], rid, info, raw)
                                if finding:
                                    info_hits.append(finding)
                        except Exception as e:
                            logger.debug(f"Error aplicando regla info {rid}: {e}")
                
                for rid, info in rules['motor_a'].items():
                    if syntax not in info['scope']:
                        continue
                    try:
                        if not info['pattern'].search(raw):
                            continue
                        
                        if rid == 'MQ_API_USAGE':
                            if seen_mq:
                                continue
                            seen_mq = True
                        
                        finding = build_finding(file_name, item['linea'], rid, info, raw)
                        if finding:
                            motor_a.append(finding)
                    except Exception as e:
                        logger.debug(f"Error aplicando regla motor_a {rid}: {e}")
        
        return motor_a, motor_b, info_hits
    except Exception as e:
        logger.error(f"Error aplicando reglas: {e}")
        return [], [], []

def compute_stats(mapped):
    """Calcula estadísticas del mapeo."""
    try:
        total = len(mapped)
        code = sum(1 for x in mapped if x['naturaleza'] == 'CODIGO_ACTIVO')
        comments = sum(1 for x in mapped if x['naturaleza'] == 'COMENTARIO')
        empty = sum(1 for x in mapped if x['naturaleza'] == 'VACIA')
        
        return {
            'total_lineas': total,
            'lineas_codigo_activo': code,
            'lineas_comentarios': comments,
            'lineas_vacias': empty,
            'porcentaje_codigo_activo': round((code / total * 100) if total else 0, 2),
            'porcentaje_comentarios': round((comments / total * 100) if total else 0, 2),
            'porcentaje_vacias': round((empty / total * 100) if total else 0, 2),
        }
    except Exception as e:
        logger.error(f"Error calculando estadísticas: {e}")
        return {
            'total_lineas': 0,
            'lineas_codigo_activo': 0,
            'lineas_comentarios': 0,
            'lineas_vacias': 0,
            'porcentaje_codigo_activo': 0,
            'porcentaje_comentarios': 0,
            'porcentaje_vacias': 0,
        }

# ============================================================================
# FUNCIONES DE GENERACIÓN DE REPORTES
# ============================================================================

def write_step1_report(out_path, meta, mapped, motor_a, motor_b, info_hits):
    """Escribe el reporte individual de un archivo."""
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('=' * 100 + '\n')
            f.write(f"REPORTE INDIVIDUAL IBM i :: {meta['archivo_nombre']}\n")
            f.write('=' * 100 + '\n')
            f.write(f"Ruta original: {meta['ruta_completa']}\n")
            f.write(f"Sintaxis detectada: {meta['sintaxis_ibm']}\n")
            f.write(f"Encoding usado: {meta['encoding_detectado']} (confianza {meta['confianza_encoding']}%)\n")
            f.write(f"Tamaño bytes: {meta['tamano_bytes']}\n")
            f.write(f"SHA-256: {meta['hash_sha256']}\n")
            f.write(f"Fecha análisis: {meta['fecha_analisis']}\n")
            f.write('-' * 100 + '\n')
            f.write('MÉTRICAS\n')
            stats = meta['estadisticas']
            f.write(f"Total líneas: {stats['total_lineas']}\n")
            f.write(f"Código activo: {stats['lineas_codigo_activo']} ({stats['porcentaje_codigo_activo']}%)\n")
            f.write(f"Comentarios: {stats['lineas_comentarios']} ({stats['porcentaje_comentarios']}%)\n")
            f.write(f"Vacías: {stats['lineas_vacias']} ({stats['porcentaje_vacias']}%)\n")
            f.write('-' * 100 + '\n')
            f.write('EXPLICACIÓN LÍNEA A LÍNEA\n')
            for item in mapped:
                f.write(f"L{item['linea']:05d} [{item['naturaleza']}] {item['contenido']}\n")
                f.write(f"  -> {item['explicacion_tecnica']}\n")
            
            unknown = [x for x in mapped if x['naturaleza'] == 'CODIGO_ACTIVO' and x['explicacion_tecnica'] == 'Instrucción u operación estándar nativa.']
            f.write('-' * 100 + '\n')
            f.write('LÍNEAS NO RECONOCIDAS / OPERACIONES ESTÁNDAR\n')
            if unknown:
                for x in unknown:
                    f.write(f"L{x['linea']:05d} | {x['contenido']}\n")
            else:
                f.write('Sin líneas pendientes.\n')
            
            f.write('-' * 100 + '\n')
            f.write('HALLAZGOS MOTOR A (CÓDIGO)\n')
            if motor_a:
                for i, h in enumerate(motor_a, 1):
                    h['id_global'] = f'A-{i:03d}'
                    f.write(f"A-{i:03d} | L{h['linea']} | {h['criticidad']} | {h['categoria']} | {h['regla']}\n")
                    f.write(f"  Match: {h['match_formateado']}\n")
                    f.write(f"  Descripción: {h['descripcion']}\n")
                    f.write(f"  Mitigación: {h['mitigacion']}\n")
            else:
                f.write('Sin hallazgos.\n')
            
            f.write('-' * 100 + '\n')
            f.write('HALLAZGOS MOTOR B (COMENTARIOS)\n')
            if motor_b:
                for i, h in enumerate(motor_b, 1):
                    h['id_global'] = f'B-{i:03d}'
                    f.write(f"B-{i:03d} | L{h['linea']} | {h['criticidad']} | {h['categoria']} | {h['regla']}\n")
                    f.write(f"  Match: {h['match_formateado']}\n")
                    f.write(f"  Descripción: {h['descripcion']}\n")
                    f.write(f"  Mitigación: {h['mitigacion']}\n")
            else:
                f.write('Sin hallazgos.\n')
            
            f.write('-' * 100 + '\n')
            f.write('MAPEO INFORMATIVO / DEPENDENCIAS\n')
            if info_hits:
                for i, h in enumerate(info_hits, 1):
                    f.write(f"I-{i:03d} | L{h['linea']} | {h['categoria']} | {h['regla']}\n")
                    f.write(f"  Match: {h['match_formateado']}\n")
                    f.write(f"  Descripción: {h['descripcion']}\n")
            else:
                f.write('Sin mapeos informativos.\n')
    except Exception as e:
        logger.error(f"Error escribiendo reporte {out_path}: {e}")

def md_escape(text):
    """Escapa caracteres especiales para Markdown."""
    return str(text).replace('|', '\\|')

def write_master_report(out_path, target_info, files_data, all_findings):
    """Escribe el reporte maestro consolidado."""
    try:
        total_a = sum(len(x['hallazgos_motor_a']) for x in files_data)
        total_b = sum(len(x['hallazgos_motor_b']) for x in files_data)
        total_info = sum(len(x['mapeo_informativo']) for x in files_data)
        sev = Counter(f['criticidad'] for f in all_findings)
        
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('# Informe de Auditoría de Seguridad Contextual IBM i\n\n')
            f.write('## Ficha técnica\n\n')
            f.write('| Parámetro | Valor |\n| :--- | :--- |\n')
            f.write(f"| Objetivo | `{md_escape(target_info['objetivo'])}` |\n")
            f.write(f"| Tipo objetivo | `{target_info['tipo_objetivo']}` |\n")
            f.write(f"| Ruta | `{md_escape(target_info['ruta_absoluta'])}` |\n")
            f.write(f"| Fecha análisis | {target_info['fecha_analisis']} |\n")
            f.write(f"| Archivos analizados | {len(files_data)} |\n")
            f.write(f"| Hallazgos consolidados | {len(all_findings)} |\n\n")
            
            f.write('## Dashboard\n\n')
            f.write('| Archivo Fuente | Tipo Sintaxis | Líneas Totales | Alertas Motor A | Fugas Motor B | Info / Map | Reporte Step 1 |\n')
            f.write('| :--- | :---: | :---: | :---: | :---: | :---: | :--- |\n')
            for fd in files_data:
                m = fd['metadata']
                report = Path(m['reporte_step1_txt']).name
                f.write(f"| {m['archivo_nombre']} | {m['sintaxis_ibm']} | {m['estadisticas']['total_lineas']} | {len(fd['hallazgos_motor_a'])} | {len(fd['hallazgos_motor_b'])} | {len(fd['mapeo_informativo'])} | `{report}` |\n")
            
            f.write('\n```text\n')
            f.write(f'Motor A (Código Activo): {total_a} hallazgos\n')
            f.write(f'Motor B (Comentarios): {total_b} hallazgos\n')
            f.write(f'Info / Mapeo: {total_info} hallazgos\n')
            f.write('```\n\n')
            
            f.write('## Métricas globales\n\n')
            f.write(f"- Altas: {sev.get('Alta', 0)}\n")
            f.write(f"- Medias: {sev.get('Media', 0)}\n")
            f.write(f"- Bajas: {sev.get('Baja', 0)}\n\n")
            
            f.write('---\n\n')
            f.write('## Hallazgos por Archivo\n\n')
            
            global_counter = 0
            
            for fd in files_data:
                m = fd['metadata']
                nombre_archivo = m['archivo_nombre']
                sintaxis = m['sintaxis_ibm']
                h_a = fd['hallazgos_motor_a']
                h_b = fd['hallazgos_motor_b']
                h_info = fd['mapeo_informativo']
                
                total_archivo = len(h_a) + len(h_b) + len(h_info)
                
                f.write(f'### 📄 Archivo: `{nombre_archivo}`\n\n')
                f.write(f'- **Sintaxis:** `{sintaxis}`\n')
                f.write(f'- **Líneas totales:** {m["estadisticas"]["total_lineas"]}\n')
                f.write(f'- **SHA-256:** `{m["hash_sha256"]}`\n')
                f.write(f'- **Total hallazgos:** {total_archivo}\n\n')
                
                if total_archivo == 0:
                    f.write('✅ *No se detectaron hallazgos en este archivo.*\n\n')
                    f.write('---\n\n')
                    continue
                
                if h_a:
                    f.write('#### 💻 Motor A: Código Ejecutable Activo\n\n')
                    for sev_level in ['Alta', 'Media', 'Baja']:
                        items = [x for x in h_a if x['criticidad'] == sev_level]
                        if not items:
                            continue
                        f.write(f'**Severidad: {sev_level}** ({len(items)})\n\n')
                        for h in sorted(items, key=lambda x: x['linea']):
                            global_counter += 1
                            h['id_global_unico'] = f'F-{global_counter:05d}'
                            f.write(f"##### [{h['categoria']}] {h['id_global_unico']} — Línea `{h['linea']}`\n")
                            f.write(f"- **Regla:** `{h['regla']}`\n")
                            f.write(f"- **Match:** `{md_escape(h['match_formateado'])}`\n")
                            f.write(f"- **Descripción:** {h['descripcion']}\n")
                            f.write(f"- **CWE / OWASP:** {h['cwe']} / {h['owasp']}\n")
                            f.write(f"- **Mitigación:** {h['mitigacion']}\n")
                            f.write(f"- **Referencias:** {', '.join(h['referencias'])}\n\n")
                
                if h_b:
                    f.write('#### 💬 Motor B: Comentarios y Metadatos\n\n')
                    for sev_level in ['Alta', 'Media', 'Baja']:
                        items = [x for x in h_b if x['criticidad'] == sev_level]
                        if not items:
                            continue
                        f.write(f'**Severidad: {sev_level}** ({len(items)})\n\n')
                        for h in sorted(items, key=lambda x: x['linea']):
                            global_counter += 1
                            h['id_global_unico'] = f'F-{global_counter:05d}'
                            f.write(f"##### [{h['categoria']}] {h['id_global_unico']} — Línea `{h['linea']}`\n")
                            f.write(f"- **Regla:** `{h['regla']}`\n")
                            f.write(f"- **Match:** `{md_escape(h['match_formateado'])}`\n")
                            f.write(f"- **Descripción:** {h['descripcion']}\n")
                            f.write(f"- **CWE / OWASP:** {h['cwe']} / {h['owasp']}\n")
                            f.write(f"- **Mitigación:** {h['mitigacion']}\n")
                            f.write(f"- **Referencias:** {', '.join(h['referencias'])}\n\n")
                
                if h_info:
                    f.write('#### 🗺️ Mapeo Informativo / Dependencias\n\n')
                    f.write(f'**Total:** {len(h_info)} hallazgos\n\n')
                    for h in sorted(h_info, key=lambda x: x['linea']):
                        global_counter += 1
                        h['id_global_unico'] = f'F-{global_counter:05d}'
                        f.write(f"##### [{h['categoria']}] {h['id_global_unico']} — Línea `{h['linea']}`\n")
                        f.write(f"- **Regla:** `{h['regla']}`\n")
                        f.write(f"- **Match:** `{md_escape(h['match_formateado'])}`\n")
                        f.write(f"- **Descripción:** {h['descripcion']}\n")
                        f.write(f"- **Mitigación:** {h['mitigacion']}\n")
                        f.write(f"- **Referencias:** {', '.join(h['referencias'])}\n\n")
                
                f.write('---\n\n')
            
            f.write('## Resumen Global de Hallazgos\n\n')
            if not all_findings:
                f.write('Sin hallazgos.\n')
            else:
                f.write('| ID | Archivo | Línea | Severidad | Categoría | Regla |\n')
                f.write('| :--- | :--- | :---: | :---: | :--- | :--- |\n')
                sorted_findings = sorted(all_findings, key=lambda x: (x['archivo'], x['linea']))
                for idx, h in enumerate(sorted_findings, 1):
                    f.write(f"| F-{idx:05d} | `{h['archivo']}` | {h['linea']} | {h['criticidad']} | {h['categoria']} | `{h['regla']}` |\n")
    except Exception as e:
        logger.error(f"Error escribiendo reporte maestro {out_path}: {e}")

# ============================================================================
# FUNCIONES PRINCIPALES
# ============================================================================

def output_folder(target_path, timestamp):
    """Determina la carpeta de salida."""
    print('¿Dónde deseas guardar los reportes?')
    print('1. Enter o 1 = en la carpeta donde corre el script')
    print('2. 2 = en la misma carpeta del código analizado')
    print('3. 3 = escribir una ruta manual')
    choice = input('Opción [Enter=1]: ').strip() or '1'
    
    if choice == '1':
        root = Path.cwd()
    elif choice == '2':
        root = Path(target_path).resolve().parent if Path(target_path).is_file() else Path(target_path).resolve()
    elif choice == '3':
        manual = input('Ruta manual: ').strip().strip('"').strip("'")
        root = Path(manual)
    else:
        root = Path.cwd()
    
    folder = root / f'resultados_ibm_{timestamp}'
    folder.mkdir(parents=True, exist_ok=True)
    return folder

def print_banner():
    """Imprime el banner del script."""
    print('=' * 78)
    print(f' {APP_NAME} :: versión {APP_VERSION}')
    print(' Suite unificada para IBM i / AS400 - RPG / SQL / DB / CLP / PF / DSPF')
    print(' No modifica archivos originales. Solo lectura, análisis y generación de reportes.')
    print(' Manejo robusto de errores y diccionarios mejorados.')
    print('=' * 78)
    print()

def analyze_file(path, out_dir, run_ts_human, run_ts_file):
    """Analiza un archivo individual con manejo robusto de errores."""
    try:
        lines_gen = read_lines(path)
        
        sample_lines = []
        enc_used = 'latin-1'
        conf_used = 0.0
        
        for i, (line, enc, conf) in enumerate(lines_gen):
            if i >= 250:
                break
            sample_lines.append(line)
            enc_used = enc
            conf_used = conf
        
        def combined_iter():
            for line in sample_lines:
                yield line, enc_used, conf_used
            for item in lines_gen:
                yield item
        
        syntax = detect_syntax(combined_iter(), path)
        
        lines_gen = read_lines(path)
        mapped = map_lines(lines_gen, syntax)
        
        motor_a, motor_b, info_hits = apply_rules(mapped, os.path.basename(path), syntax)
        stats = compute_stats(mapped)
        
        prefix = f"analisis_{syntax.lower() if syntax != 'SQL' else 'sql'}_detallado_individual_{Path(path).stem}_{run_ts_file}.txt"
        step1 = out_dir / prefix
        
        meta = {
            'archivo_nombre': os.path.basename(path),
            'ruta_completa': str(Path(path).resolve()),
            'sintaxis_ibm': syntax,
            'encoding_detectado': enc_used,
            'confianza_encoding': round(conf_used * 100, 1),
            'hash_sha256': sha256_file(path),
            'tamano_bytes': Path(path).stat().st_size,
            'fecha_analisis': run_ts_human,
            'estadisticas': stats,
            'reporte_step1_txt': str(step1)
        }
        
        write_step1_report(step1, meta, mapped, motor_a, motor_b, info_hits)
        
        return {
            'metadata': meta,
            'mapeo_lineal_detallado': mapped,
            'hallazgos_motor_a': motor_a,
            'hallazgos_motor_b': motor_b,
            'mapeo_informativo': info_hits,
            'error': None
        }
    except Exception as e:
        logger.error(f"Error analizando archivo {path}: {e}")
        return {
            'metadata': {
                'archivo_nombre': os.path.basename(path),
                'ruta_completa': str(Path(path).resolve()),
                'sintaxis_ibm': 'ERROR',
                'encoding_detectado': 'N/A',
                'confianza_encoding': 0.0,
                'hash_sha256': sha256_file(path),
                'tamano_bytes': 0,
                'fecha_analisis': run_ts_human,
                'estadisticas': compute_stats([]),
                'reporte_step1_txt': ''
            },
            'mapeo_lineal_detallado': [],
            'hallazgos_motor_a': [],
            'hallazgos_motor_b': [],
            'mapeo_informativo': [],
            'error': str(e)
        }

def main():
    """Función principal del script."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--archivo', help='Archivo a analizar')
    parser.add_argument('-f', '--folder', dest='carpeta', help='Carpeta a analizar recursivamente')
    args = parser.parse_args()
    
    if not args.archivo and not args.carpeta:
        parser.error('Debes indicar -a o -f')
    
    print_banner()
    
    target = args.archivo or args.carpeta
    run_dt = datetime.now()
    run_ts_human = run_dt.strftime('%Y-%m-%d %H:%M:%S')
    run_ts_file = run_dt.strftime(TS_FORMAT)
    
    try:
        out_dir = output_folder(target, run_ts_file)
    except Exception as e:
        logger.error(f"Error creando carpeta de salida: {e}")
        out_dir = Path.cwd() / f'resultados_ibm_{run_ts_file}'
        out_dir.mkdir(parents=True, exist_ok=True)
    
    if args.archivo:
        files = [args.archivo]
        target_type = 'archivo'
    else:
        files = collect_files(args.carpeta)
        target_type = 'carpeta'
    
    print(f'[*] Archivos a analizar: {len(files)}')
    
    results = []
    errors = []
    for idx, path in enumerate(files, 1):
        print(f'[{idx}/{len(files)}] Analizando: {path}')
        result = analyze_file(path, out_dir, run_ts_human, run_ts_file)
        results.append(result)
        if result['error']:
            errors.append({'archivo': path, 'error': result['error']})
    
    all_findings = []
    for r in results:
        if not r['error']:
            all_findings.extend(r['hallazgos_motor_a'])
            all_findings.extend(r['hallazgos_motor_b'])
            all_findings.extend(r['mapeo_informativo'])
    
    summary = Counter(x['criticidad'] for x in all_findings)
    
    payload = {
        'tool_info': {
            'name': APP_NAME,
            'version': APP_VERSION,
            'generated_at': run_ts_human
        },
        'target_info': {
            'objetivo': Path(target).name,
            'tipo_objetivo': target_type,
            'ruta_absoluta': str(Path(target).resolve()),
            'fecha_analisis': run_ts_human,
        },
        'summary': {
            'archivos_analizados': len(results),
            'archivos_con_error': len(errors),
            'hallazgos_totales': len(all_findings),
            'hallazgos_alta': summary.get('Alta', 0),
            'hallazgos_media': summary.get('Media', 0),
            'hallazgos_baja': summary.get('Baja', 0),
        },
        'files': results,
        'findings': all_findings,
        'errors': errors
    }
    
    json_path = out_dir / f'FINDINGS_AUDITORIA_IBM_{run_ts_file}.json'
    md_path = out_dir / f'REPORTE_MASTER_IBM_{run_ts_file}.md'
    
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Error escribiendo JSON: {e}")
    
    write_master_report(md_path, payload['target_info'], results, all_findings)
    
    print('\n' + '=' * 78)
    print('ANÁLISIS FINALIZADO')
    print('=' * 78)
    print(f'Salida: {out_dir}')
    print(f'JSON consolidado: {json_path}')
    print(f'Reporte Master MD: {md_path}')
    print(f'Archivos analizados: {len(results)}')
    print(f'Archivos con error: {len(errors)}')
    if errors:
        print('Errores detectados:')
        for err in errors:
            print(f"  - {err['archivo']}: {err['error']}")
    print(f'Hallazgos totales: {len(all_findings)}')
    print(f"Altas/Medias/Bajas: {summary.get('Alta', 0)}/{summary.get('Media', 0)}/{summary.get('Baja', 0)}")
    print('=' * 78)

if __name__ == '__main__':
    main()