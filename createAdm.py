import os
import getpass
from run import create_app, db, User

def create_admin_user():
    app = create_app()
    with app.app_context():
        admin_username = input("Enter admin username (default is 'admin'): ") or 'admin'
        admin_password = getpass.getpass("Enter admin password: ")
        confirm_password = getpass.getpass("Confirm admin password: ")

        if admin_password != confirm_password:
            print("Error: Passwords do not match.")
            return

        existing_admin = User.query.filter_by(username=admin_username).first()
        if existing_admin:
            print(f"Admin user '{admin_username}' already exists.")
            overwrite = input("Do you want to overwrite the existing admin user? (y/n): ")
            if overwrite.lower() != 'y':
                return
            db.session.delete(existing_admin)

        admin_user = User(username=admin_username)
        admin_user.set_password(admin_password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{admin_username}' created successfully.")

if __name__ == "__main__":
    create_admin_user()