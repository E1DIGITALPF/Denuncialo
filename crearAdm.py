import os
import getpass
from run import create_app, db, User

def create_admin_user():
    app = create_app()
    with app.app_context():
        admin_username = input("Coloca el nombre de usuario ('admin' es el usuario por defecto): ") or 'admin'
        admin_password = getpass.getpass("Coloca una contraseña: ")
        confirm_password = getpass.getpass("Confirma la contraseña: ")

        if admin_password != confirm_password:
            print("Error: Las contraseñas no coinciden.")
            return

        existing_admin = User.query.filter_by(username=admin_username).first()
        if existing_admin:
            print(f"El usuario admin '{admin_username}' ya existe.")
            overwrite = input("¿Quieres sobreescribir este usuario? (s/n): ")
            if overwrite.lower() != 's':
                return
            db.session.delete(existing_admin)

        admin_user = User(username=admin_username)
        admin_user.set_password(admin_password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Usuario admin '{admin_username}' creado satisfactoriamente.")

if __name__ == "__main__":
    create_admin_user()