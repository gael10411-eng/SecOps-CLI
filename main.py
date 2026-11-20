
import os
from pathlib import Path
from getpass import getpass

from dotenv import load_dotenv

from modules.auth_crypto import (
    encrypt_file,
    decrypt_file,
    save_credentials,
    load_credentials,
    CryptoError,
    AuthenticationError,
    InvalidFileError
)


# ==========================================
# CONFIGURACIÓN GENERAL
# ==========================================

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "SpecOps-CLI")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

DATA_DIR = Path("data")
VAULT_PATH = DATA_DIR / "credentials.enc"


# ==========================================
# INTERFAZ DE CONSOLA
# ==========================================

def show_header():
    """Muestra el encabezado de la aplicación."""

    os.system("cls" if os.name == "nt" else "clear")

    print("=" * 48)
    print(f"          {APP_NAME}")
    print("       Security Operations CLI")
    print("=" * 48)
    print(f" Version: {APP_VERSION}")
    print(" Security module: Active")
    print("=" * 48)


def show_menu():
    """Muestra las opciones disponibles."""

    print("\n[1] Cifrar archivo")
    print("[2] Descifrar archivo")
    print("[3] Guardar credenciales")
    print("[4] Consultar credenciales")
    print("[0] Salir")

    print("\n" + "-" * 48)


def pause():
    """Espera la confirmación del usuario."""

    input("\nPresiona ENTER para continuar...")


def confirm_overwrite(path):
    """Solicita confirmación antes de sobrescribir."""

    if path.exists():
        answer = input(
            f"El archivo {path} ya existe. "
            "¿Deseas sobrescribirlo? (s/n): "
        ).strip().lower()

        return answer == "s"

    return True


# ==========================================
# CIFRADO DE ARCHIVOS
# ==========================================

def encrypt_operation():
    """Solicita los datos necesarios para cifrar."""

    print("\n--- CIFRADO DE ARCHIVOS ---")

    input_path = Path(
        input("Ruta del archivo original: ").strip().strip('"')
    )

    if not input_path.is_file():
        print("[ERROR] No se encontró el archivo.")
        return

    default_output = input_path.with_name(
        input_path.name + ".enc"
    )

    output_value = input(
        f"Ruta de salida [{default_output}]: "
    ).strip().strip('"')

    output_path = Path(output_value) if output_value else default_output

    if input_path.resolve() == output_path.resolve():
        print("[ERROR] El archivo de salida debe ser diferente.")
        return

    if not confirm_overwrite(output_path):
        print("[INFO] Operación cancelada.")
        return

    password = getpass("Contraseña maestra: ")

    encrypt_file(
        input_path,
        output_path,
        password
    )

    print(f"\n[OK] Archivo cifrado: {output_path}")


# ==========================================
# DESCIFRADO DE ARCHIVOS
# ==========================================

def decrypt_operation():
    """Solicita los datos necesarios para descifrar."""

    print("\n--- DESCIFRADO DE ARCHIVOS ---")

    input_path = Path(
        input("Ruta del archivo cifrado: ").strip().strip('"')
    )

    if not input_path.is_file():
        print("[ERROR] No se encontró el archivo.")
        return

    if input_path.name.endswith(".enc"):
        default_output = input_path.with_name(
            input_path.name[:-4]
        )
    else:
        default_output = input_path.with_name(
            "decrypted_" + input_path.name
        )

    output_value = input(
        f"Ruta de salida [{default_output}]: "
    ).strip().strip('"')

    output_path = Path(output_value) if output_value else default_output

    if input_path.resolve() == output_path.resolve():
        print("[ERROR] El archivo de salida debe ser diferente.")
        return

    if not confirm_overwrite(output_path):
        print("[INFO] Operación cancelada.")
        return

    password = getpass("Contraseña maestra: ")

    decrypt_file(
        input_path,
        output_path,
        password
    )

    print(f"\n[OK] Archivo recuperado: {output_path}")


# ==========================================
# GUARDAR CREDENCIALES
# ==========================================

def save_credentials_operation():
    """Guarda o actualiza credenciales en el almacén cifrado."""

    print("\n--- ALMACENAMIENTO DE CREDENCIALES ---")

    service = input("Servicio o plataforma: ").strip()
    username = input("Usuario: ").strip()
    account_password = getpass("Contraseña de la cuenta: ")

    if not service or not username or not account_password:
        print("[ERROR] Todos los campos son obligatorios.")
        return

    master_password = getpass("Contraseña maestra del almacén: ")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if VAULT_PATH.exists():
        credentials = load_credentials(
            VAULT_PATH,
            master_password
        )
    else:
        credentials = {}

    credentials[service] = {
        "username": username,
        "password": account_password
    }

    save_credentials(
        credentials,
        VAULT_PATH,
        master_password
    )

    print(f"\n[OK] Credenciales guardadas para: {service}")


# ==========================================
# CONSULTAR CREDENCIALES
# ==========================================

def load_credentials_operation():
    """Recupera credenciales desde el almacén cifrado."""

    print("\n--- CONSULTA DE CREDENCIALES ---")

    if not VAULT_PATH.is_file():
        print("[ERROR] Todavía no existe un almacén de credenciales.")
        return

    master_password = getpass("Contraseña maestra: ")

    credentials = load_credentials(
        VAULT_PATH,
        master_password
    )

    if not credentials:
        print("[INFO] No existen credenciales almacenadas.")
        return

    print("\nServicios registrados:")

    services = list(credentials.keys())

    for index, service in enumerate(services, start=1):
        print(f"[{index}] {service}")

    try:
        selection = int(input("\nSelecciona un servicio: "))

        if selection < 1 or selection > len(services):
            print("[ERROR] Selección inválida.")
            return

    except ValueError:
        print("[ERROR] Debes introducir un número.")
        return

    selected_service = services[selection - 1]
    account = credentials[selected_service]

    print("\n--- INFORMACIÓN RECUPERADA ---")
    print(f"Servicio: {selected_service}")
    print(f"Usuario: {account.get('username', '')}")
    print(f"Contraseña: {account.get('password', '')}")


# ==========================================
# CONTROL PRINCIPAL
# ==========================================

def main():
    """Ejecuta el menú principal de SpecOps-CLI."""

    while True:

        show_header()
        show_menu()

        option = input("Selecciona una opción: ").strip()

        try:

            if option == "1":
                encrypt_operation()

            elif option == "2":
                decrypt_operation()

            elif option == "3":
                save_credentials_operation()

            elif option == "4":
                load_credentials_operation()

            elif option == "0":
                print("\nCerrando SpecOps-CLI...")
                print("Hasta pronto.")
                break

            else:
                print("\n[ERROR] Opción no válida.")

        except AuthenticationError:
            print("\n[ERROR] Contraseña incorrecta o archivo modificado.")

        except InvalidFileError as error:
            print(f"\n[ERROR] Archivo inválido: {error}")

        except CryptoError as error:
            print(f"\n[ERROR] Error criptográfico: {error}")

        except FileNotFoundError as error:
            print(f"\n[ERROR] Archivo no encontrado: {error}")

        except PermissionError:
            print("\n[ERROR] No tienes permisos para acceder al archivo.")

        except (OSError, ValueError) as error:
            print(f"\n[ERROR] No se pudo completar la operación: {error}")

        except KeyboardInterrupt:
            print("\n\n[INFO] Operación interrumpida.")

        if option != "0":
            pause()


# ==========================================
# PUNTO DE ENTRADA
# ==========================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSpecOps-CLI finalizado.")
