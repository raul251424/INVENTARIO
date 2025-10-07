# crear_admin.py

# Importa las herramientas necesarias desde tu aplicación principal
from app import app, db, User

def crear_super_usuario():
    """
    Esta función crea un usuario administrador de forma interactiva.
    """
    # Le dice a Flask que estamos trabajando dentro del contexto de la app
    with app.app_context():
        print("--- Creación de Usuario Administrador ---")
        
        # Pedir datos por consola
        nombre = input("Nombre del administrador: ")
        email = input("Correo electrónico: ")
        password = input("Contraseña: ")

        # Verificar si el email ya existe
        if User.query.filter_by(email=email).first():
            print(f"\nError: El correo '{email}' ya está registrado. Inténtalo de nuevo.")
            return

        # Crear el nuevo usuario
        admin_user = User(
            nombre=nombre,
            email=email,
            es_admin=True
        )
        admin_user.set_password(password) # Usamos el método para hashear la contraseña

        # Guardar en la base de datos
        try:
            db.session.add(admin_user)
            db.session.commit()
            print(f"\n¡Éxito! El administrador '{nombre}' ha sido creado.")
        except Exception as e:
            db.session.rollback()
            print(f"\nError al guardar en la base de datos: {e}")

# Esta línea hace que la función se ejecute cuando corres "python crear_admin.py"
if __name__ == '__main__':
    crear_super_usuario()