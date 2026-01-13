import os

def auditar_documentacion_python(path_raiz="."):
    """
    Identifica directorios con scripts de Python que carecen de README.md.
    Criterio: Presencia de *.py Y ausencia de README.md (case-insensitive).
    """
    for root, _, files in os.walk(path_raiz):
        # Normalización a minúsculas para comparaciones case-insensitive
        files_lower = [f.lower() for f in files]
        
        tiene_python = any(f.endswith(".py") for f in files_lower)
        tiene_readme = "readme.md" in files_lower

        if tiene_python and not tiene_readme:
            print(f"[MISSING README] {os.path.abspath(root)}")

if __name__ == "__main__":
    auditar_documentacion_python(".")