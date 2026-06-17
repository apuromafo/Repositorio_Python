//===================================================================
// Archivo: demo_vulnerabilidad.rpgle
// Propósito: Miembro fuente de prueba con patrones vulnerables reales
//===================================================================

// --- MOTOR A: HALLAZGOS CRÍTICOS EN CÓDIGO ACTIVO ---
CTL-OPT USRPRF(*OWNER) DEBUG(*YES); 
// Reglas gatilladas: ADOPT_AUTHORITY_POTENTIAL y DEBUG_CONFIG

DCL-S CLAVE CHAR(10) INZ('SysAdmin99!'); 
// Regla gatillada: HARDCODED_PASSWORDS

EXEC SQL EXECUTE IMMEDIATE :SqlDinamico; 
// Regla gatillada: EMBEDDED_SQL_DYNAMIC (Riesgo de Inyección SQL)

DUMP;
// Regla gatillada: DUMP_STATEMENTS

// --- MOTOR B: COMENTARIOS Y METADATOS SENSIBLES ---
// TODO: Credenciales de respaldo temporales en producción -> Admin2026!
// Regla gatillada: TODO_FIXME_SENSITIVE

// FIXME: Acceder vía SSH usando la IP interna 10.140.22.9
// Regla gatillada: COMMENT_IP_OR_PATH

// --- INFO RULES: MAPEO E INVENTARIO DE ARQUITECTURA ---
DCL-S Servidor_IP CHAR(15) INZ('192.168.1.50');
// Mapeado como: IP_ADDRESSES

PGM
    CHGSYSVAL SYSVAL(QSECURITY) VALUE('30')
    /* Regla gatillada: SECURITY_DOWNGRADE_SYSVAL */

    MONMSG MSGID(CPF0000)
    /* Mapeado como: BLIND_MONMSG */

    CALL PGM(QCMDEXC) PARM(&CMD 200)
    /* Regla gatillada: COMMAND_INJECTION_QCMDEXC */
ENDPGM
