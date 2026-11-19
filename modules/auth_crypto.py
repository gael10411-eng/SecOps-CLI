
import os
import json
import hmac
import base64
import hashlib
import secrets
import tempfile

from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


# ==========================================
# CONFIGURACIÓN DEL MÓDULO
# ==========================================

ALGORITHM = "PBKDF2-HMAC-SHA256"
ITERATIONS = 600_000
SALT_SIZE = 16
KEY_SIZE = 32

FILE_MAGIC = b"GAELCRYPT1"
HASH_ALGORITHM = "pbkdf2_sha256"


# ==========================================
# EXCEPCIONES PERSONALIZADAS
# ==========================================

class CryptoError(Exception):
    """Error general del módulo criptográfico."""
    pass


class AuthenticationError(CryptoError):
    """Contraseña incorrecta o autenticación fallida."""
    pass


class InvalidFileError(CryptoError):
    """Archivo cifrado inválido o formato desconocido."""
    pass


# ==========================================
# VALIDACIÓN DE CONTRASEÑAS
# ==========================================

def _validate_password(password):
    """
    Comprueba que la contraseña sea válida.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("La contraseña no puede estar vacía.")

    if len(password.encode("utf-8")) > 1024:
        raise ValueError("La contraseña supera el tamaño permitido.")


# ==========================================
# DERIVACIÓN DE CLAVES
# ==========================================

def _derive_key(password, salt):
    """
    Genera una clave criptográfica mediante PBKDF2.
    """

    _validate_password(password)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=KEY_SIZE
    )

    return base64.urlsafe_b64encode(key)


# ==========================================
# CIFRADO Y DESCIFRADO INTERNO
# ==========================================

def _encrypt_bytes(data, password):
    """
    Cifra datos binarios utilizando Fernet.
    """

    if not isinstance(data, bytes):
        raise TypeError("Los datos deben ser binarios.")

    _validate_password(password)

    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(password, salt)

    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)

    return FILE_MAGIC + salt + encrypted_data


def _decrypt_bytes(encrypted_data, password):
    """
    Descifra datos binarios y verifica su integridad.
    """

    _validate_password(password)

    header_size = len(FILE_MAGIC) + SALT_SIZE

    if not isinstance(encrypted_data, bytes):
        raise TypeError("Los datos deben ser binarios.")

    if (
        len(encrypted_data) <= header_size
        or not encrypted_data.startswith(FILE_MAGIC)
    ):
        raise InvalidFileError("El formato del archivo no es válido.")

    salt_start = len(FILE_MAGIC)
    salt_end = salt_start + SALT_SIZE

    salt = encrypted_data[salt_start:salt_end]
    token = encrypted_data[salt_end:]

    key = _derive_key(password, salt)

    try:
        cipher = Fernet(key)
        return cipher.decrypt(token)

    except InvalidToken:
        raise AuthenticationError(
            "Contraseña incorrecta o archivo modificado."
        )


# ==========================================
# ESCRITURA SEGURA DE ARCHIVOS
# ==========================================

def _write_atomic(path, data):
    """
    Escribe datos mediante un archivo temporal
    y reemplaza el destino al finalizar.
    """

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            delete=False
        ) as temp_file:

            temp_path = Path(temp_file.name)
            temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_path, path)

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


# ==========================================
# CIFRADO DE ARCHIVOS
# ==========================================

def encrypt_file(input_path, output_path, password):
    """
    Cifra un archivo y guarda el resultado.

    Devuelve la ruta del archivo cifrado.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("El archivo de origen no existe.")

    _validate_password(password)

    data = input_path.read_bytes()
    encrypted_data = _encrypt_bytes(data, password)

    _write_atomic(output_path, encrypted_data)

    return output_path


# ==========================================
# DESCIFRADO DE ARCHIVOS
# ==========================================

def decrypt_file(input_path, output_path, password):
    """
    Descifra un archivo y guarda su contenido original.

    Devuelve la ruta del archivo recuperado.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("El archivo cifrado no existe.")

    _validate_password(password)

    encrypted_data = input_path.read_bytes()
    decrypted_data = _decrypt_bytes(encrypted_data, password)

    _write_atomic(output_path, decrypted_data)

    return output_path


# ==========================================
# HASH DE CONTRASEÑAS
# ==========================================

def hash_password(password):
    """
    Genera un hash PBKDF2 para almacenar
    contraseñas de autenticación.
    """

    _validate_password(password)

    salt = secrets.token_bytes(SALT_SIZE)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=KEY_SIZE
    )

    salt_encoded = base64.urlsafe_b64encode(
        salt
    ).decode("ascii")

    digest_encoded = base64.urlsafe_b64encode(
        digest
    ).decode("ascii")

    return (
        f"{HASH_ALGORITHM}$"
        f"{ITERATIONS}$"
        f"{salt_encoded}$"
        f"{digest_encoded}"
    )


# ==========================================
# VERIFICACIÓN DE CONTRASEÑAS
# ==========================================


def verify_password(password, stored_hash):
    """
    Comprueba una contraseña contra su hash almacenado.
    """

    try:
        _validate_password(password)

        algorithm, iterations, salt, expected = stored_hash.split("$")

        if algorithm != HASH_ALGORITHM:
            return False

        iterations = int(iterations)

        if not 1 <= iterations <= 2_000_000:
            return False

        # Decodificación compatible con Base64 URL-safe
        salt = base64.b64decode(
            salt,
            altchars=b"-_",
            validate=True
        )

        expected = base64.b64decode(
            expected,
            altchars=b"-_",
            validate=True
        )

        if len(salt) != SALT_SIZE or len(expected) != KEY_SIZE:
            return False

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=KEY_SIZE
        )

        return hmac.compare_digest(calculated, expected)

    except (ValueError, TypeError, AttributeError):
        return False


# ==========================================
# ALMACENAMIENTO DE CREDENCIALES
# ==========================================

def save_credentials(credentials, file_path, master_password):
    """
    Guarda credenciales en un archivo cifrado.

    credentials debe ser un diccionario.
    """

    if not isinstance(credentials, dict):
        raise TypeError("Las credenciales deben ser un diccionario.")

    _validate_password(master_password)

    try:
        serialized = json.dumps(
            credentials,
            ensure_ascii=False
        ).encode("utf-8")

    except (TypeError, ValueError):
        raise CryptoError("No se pudieron serializar las credenciales.")

    encrypted_data = _encrypt_bytes(
        serialized,
        master_password
    )

    _write_atomic(file_path, encrypted_data)

    return Path(file_path)


# ==========================================
# RECUPERACIÓN DE CREDENCIALES
# ==========================================

def load_credentials(file_path, master_password):
    """
    Recupera las credenciales desde un archivo cifrado.
    """

    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError("El almacén de credenciales no existe.")

    _validate_password(master_password)

    encrypted_data = file_path.read_bytes()

    decrypted_data = _decrypt_bytes(
        encrypted_data,
        master_password
    )

    try:
        credentials = json.loads(
            decrypted_data.decode("utf-8")
        )

    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidFileError(
            "El contenido recuperado no es un almacén válido."
        )

    if not isinstance(credentials, dict):
        raise InvalidFileError(
            "La estructura de las credenciales es incorrecta."
        )

    return credentials