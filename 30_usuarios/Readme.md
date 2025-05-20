# Gestión de Usuarios Multiplataforma

Herramienta en línea de comandos (CLI) escrita en Python para gestionar usuarios en diferentes sistemas operativos: **Windows**, **Linux** y **macOS**.

Ideal para administradores de sistemas o desarrolladores que necesitan una herramienta rápida y portable para tareas básicas de gestión de usuarios.

---

## ✅ Funcionalidades

- 📋 Listar usuarios del sistema
- ➕ Crear nuevos usuarios
- ➖ Eliminar usuarios existentes
- 🧾 Ver grupos del sistema
- 👥 Ver grupos a los que pertenece un usuario
- ℹ️ Mostrar información detallada de un usuario

---

## 🖥️ Requisitos

- Python 3.6+
- Sistema operativo:
  - Windows
  - Linux
  - macOS

---

## ⚙️ Instalación

1. Clona el repositorio:

   ```bash
   git clone https://github.com/tu-usuario/gestion-usuarios.git
   cd gestion-usuarios
   ```

2. (Opcional) Crea un entorno virtual:

   ```bash
   python -m venv venv
   source venv/bin/activate  # En Linux/macOS
   venv\Scripts\activate     # En Windows
   ```

3. Ejecuta el script directamente:

   ```bash
   python usuarios.py
   ```

---

## 🧪 Uso

### Modo Interactivo (sin argumentos)
```bash
python usuarios.py
```

### Comandos Disponibles

| Comando                  | Acción                             |
|--------------------------|------------------------------------|
| `listar`                 | Lista todos los usuarios           |
| `crear <nombre>`         | Crea un nuevo usuario              |
| `eliminar <nombre>`      | Elimina un usuario                 |
| `grupos`                 | Muestra los grupos del sistema     |
| `grupos --usuario <nombre>` | Muestra los grupos de un usuario |
| `info <nombre>`          | Muestra información del usuario    |

---

## 🔐 Notas importantes

- En **Linux/macOS**, algunos comandos requieren privilegios de `root`. Usa `sudo` cuando sea necesario.
- En **Windows**, se usan comandos nativos como `net user`, por lo que no se requieren permisos adicionales (aunque sí ejecutar como administrador si es necesario).

---