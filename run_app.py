# run_app.py (Código para forzar el inicio de Flask)

from app import app
from os import getenv

# Desactivar el modo de depuración para evitar conflictos si ya estaba activo
app.debug = False 

# Ejecutamos la aplicación
if __name__ == "__main__":
    # Esto usa las configuraciones predeterminadas de host y puerto
    app.run(host='0.0.0.0', port=5000)