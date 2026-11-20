
from modules.auth_crypto import (
    hash_password,
    verify_password,
    encrypt_file,
    decrypt_file,
    save_credentials,
    load_credentials
)

# 1. Prueba de autenticación
password = "ClaveSegura123!"

hashed = hash_password(password)

assert verify_password(password, hashed)
assert not verify_password("ClaveIncorrecta", hashed)

print("[OK] Autenticación y verificación de contraseñas")


# 2. Prueba de cifrado de archivos
with open("prueba.txt", "w", encoding="utf-8") as file:
    file.write("Este es un archivo confidencial.")

encrypt_file(
    "prueba.txt",
    "prueba.enc",
    password
)

decrypt_file(
    "prueba.enc",
    "recuperado.txt",
    password
)

with open("recuperado.txt", encoding="utf-8") as file:
    assert file.read() == "Este es un archivo confidencial."

print("[OK] Cifrado y descifrado de archivos")


# 3. Prueba del almacén de credenciales
credentials = {
    "usuario": "gael",
    "token": "TOKEN_DE_PRUEBA",
    "servidor": "localhost"
}

save_credentials(
    credentials,
    "credentials.enc",
    password
)

recovered = load_credentials(
    "credentials.enc",
    password
)

assert recovered == credentials

print("[OK] Almacenamiento de credenciales")


print("\nTodas las pruebas finalizaron correctamente.")