from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(f"Clave de encriptación generada: {key.decode()}")