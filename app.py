"""
SpecOps-Web 1.0.0 — Panel web de SpecOps-CLI.

ADVERTENCIA: esta web fue construida A PROPÓSITO con vulnerabilidades
para una práctica de pentesting en un laboratorio AISLADO. No debe
exponerse a internet ni a ninguna red real. Las vulnerabilidades
intencionales están documentadas en VULNERABILIDADES.md.

Reutiliza el módulo auth_crypto.py del proyecto SpecOps-CLI del equipo
(PBKDF2-HMAC-SHA256, Fernet, almacén de credenciales cifrado).
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from modules.auth_crypto import (
    create_master_password,
    decrypt_file,
    encrypt_file,
    load_credentials,
    save_credentials,
    verify_master_password,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
ARCHIVOS_DIR = DATA_DIR / "archivos"
MASTER_PATH = DATA_DIR / "master.hash"
VAULT_PATH = DATA_DIR / "credentials.enc"
DB_PATH = DATA_DIR / "specops.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVOS_DIR.mkdir(parents=True, exist_ok=True)

APP_NAME = os.getenv("APP_NAME", "SpecOps-Web")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

# Contraseña maestra inicial (vulnerabilidad documentada: credenciales
# por defecto). Se puede cambiar con la variable MASTER_PASSWORD.
MASTER_PASSWORD_INICIAL = os.getenv("MASTER_PASSWORD", "SpecOps2026!")

app = Flask(__name__)

# Clave de sesión (vulnerabilidad documentada: clave débil y fija).
app.secret_key = os.getenv("SECRET_KEY", "specops-clave-secreta")

# Modo depuración (vulnerabilidad documentada: DEBUG expone trazas).
app.config["DEBUG"] = os.getenv("DEBUG", "True").lower() == "true"


# ==========================================
# BASE DE DATOS SQLITE (registro y usuarios)
# ==========================================

def get_db():
    """Abre la base de datos del registro de accesos."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea las tablas y los datos iniciales si no existen."""
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY,
            usuario TEXT NOT NULL,
            password TEXT NOT NULL,
            rol TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS accesos (
            id INTEGER PRIMARY KEY,
            fecha TEXT NOT NULL,
            usuario TEXT NOT NULL,
            accion TEXT NOT NULL,
            detalle TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS indice (
            id INTEGER PRIMARY KEY,
            servicio TEXT NOT NULL,
            usuario TEXT NOT NULL
        )
        """
    )
    # Usuarios iniciales (vulnerabilidad documentada: contraseñas
    # en texto plano en la base de datos).
    count = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    if count == 0:
        conn.execute(
            "INSERT INTO usuarios (usuario, password, rol) "
            "VALUES ('admin', 'admin123', 'administrador')"
        )
        conn.execute(
            "INSERT INTO usuarios (usuario, password, rol) "
            "VALUES ('operador', 'operador123', 'operador')"
        )
    conn.commit()
    conn.close()


def registrar_acceso(usuario, accion, detalle=""):
    """Registra una acción en el registro de accesos."""
    conn = get_db()
    conn.execute(
        "INSERT INTO accesos (fecha, usuario, accion, detalle) "
        "VALUES (?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         usuario, accion, detalle),
    )
    conn.commit()
    conn.close()


def asegurar_master():
    """Crea la contraseña maestra inicial si aún no existe."""
    if not MASTER_PATH.exists():
        create_master_password(MASTER_PASSWORD_INICIAL, MASTER_PATH)


# ==========================================
# AUTENTICACIÓN
# ==========================================

def requiere_login(func):
    """Decorador: exige sesión iniciada para ver la página."""
    def wrapper(*args, **kwargs):
        if not session.get("autenticado"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


@app.route("/")
def index():
    if session.get("autenticado"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    asegurar_master()
    if request.method == "POST":
        password = request.form.get("password", "")
        try:
            if verify_master_password(password, MASTER_PATH):
                # Vulnerabilidad documentada: la contraseña maestra
                # queda guardada en la cookie de sesión (legible).
                session["autenticado"] = True
                session["master"] = password
                session["usuario"] = "admin"
                registrar_acceso("admin", "inicio de sesión", "OK")
                return redirect(url_for("dashboard"))
        except FileNotFoundError:
            pass
        registrar_acceso("desconocido", "inicio de sesión", "fallido")
        flash("Contraseña maestra incorrecta.", "error")
    return render_template("login.html", app_name=APP_NAME)


@app.route("/logout")
def logout():
    registrar_acceso(
        session.get("usuario", "?"), "cierre de sesión", ""
    )
    session.clear()
    return redirect(url_for("login"))


# ==========================================
# PANEL PRINCIPAL
# ==========================================

@app.route("/dashboard")
@requiere_login
def dashboard():
    try:
        credenciales = load_credentials(VAULT_PATH, session["master"])
    except (FileNotFoundError, Exception):
        credenciales = {}
    conn = get_db()
    accesos = conn.execute(
        "SELECT * FROM accesos ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        app_name=APP_NAME,
        version=APP_VERSION,
        servicios=list(credenciales.keys()),
        accesos=accesos,
    )


# ==========================================
# ALMACÉN DE CREDENCIALES
# ==========================================

@app.route("/almacen", methods=["GET", "POST"])
@requiere_login
def almacen():
    master = session["master"]
    if request.method == "POST":
        servicio = request.form.get("servicio", "").strip()
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")
        if not servicio or not usuario or not password:
            flash("Todos los campos son obligatorios.", "error")
        else:
            try:
                credenciales = load_credentials(VAULT_PATH, master)
            except (FileNotFoundError, Exception):
                credenciales = {}
            credenciales[servicio] = {
                "username": usuario,
                "password": password,
            }
            save_credentials(credenciales, VAULT_PATH, master)
            # Índice de búsqueda en SQLite (se mantiene sincronizado).
            conn = get_db()
            conn.execute(
                "INSERT INTO indice (servicio, usuario) VALUES (?, ?)",
                (servicio, usuario),
            )
            conn.commit()
            conn.close()
            registrar_acceso(
                session["usuario"], "guardar credencial", servicio
            )
            flash(f"Credenciales guardadas para: {servicio}", "ok")
            return redirect(url_for("almacen"))
    try:
        credenciales = load_credentials(VAULT_PATH, master)
    except (FileNotFoundError, Exception):
        credenciales = {}
    return render_template(
        "almacen.html",
        app_name=APP_NAME,
        credenciales=credenciales,
    )


# ==========================================
# BÚSQUEDA (SQLi + XSS intencionales)
# ==========================================

@app.route("/buscar")
@requiere_login
def buscar():
    q = request.args.get("q", "")
    resultados = []
    if q:
        # VULNERABILIDAD INTENCIONAL (documentada): la consulta se
        # construye concatenando la entrada del usuario. Permite
        # inyección SQL (por ejemplo, UNION SELECT sobre usuarios).
        conn = get_db()
        consulta = (
            "SELECT servicio, usuario FROM indice "
            f"WHERE servicio LIKE '%{q}%'"
        )
        try:
            resultados = conn.execute(consulta).fetchall()
        except sqlite3.Error as error:
            flash(f"Error en la búsqueda: {error}", "error")
        conn.close()
        registrar_acceso(session["usuario"], "búsqueda", q)
    # VULNERABILIDAD INTENCIONAL (documentada): la plantilla muestra
    # la consulta con |safe, sin escapar HTML (XSS reflejado).
    return render_template(
        "buscar.html",
        app_name=APP_NAME,
        q=q,
        resultados=resultados,
    )


# ==========================================
# CIFRADO DE ARCHIVOS
# ==========================================

@app.route("/cifrar", methods=["GET", "POST"])
@requiere_login
def cifrar():
    if request.method == "POST":
        archivo = request.files.get("archivo")
        if not archivo or not archivo.filename:
            flash("Selecciona un archivo para cifrar.", "error")
        else:
            entrada = ARCHIVOS_DIR / archivo.filename
            archivo.save(entrada)
            salida = ARCHIVOS_DIR / (archivo.filename + ".enc")
            encrypt_file(entrada, salida, session["master"])
            registrar_acceso(
                session["usuario"], "cifrar archivo",
                archivo.filename,
            )
            flash(f"Archivo cifrado: {salida.name}", "ok")
            return redirect(url_for(
                "descargar", archivo=salida.name
            ))
    return render_template("cifrar.html", app_name=APP_NAME)


@app.route("/descifrar", methods=["GET", "POST"])
@requiere_login
def descifrar():
    if request.method == "POST":
        archivo = request.files.get("archivo")
        if not archivo or not archivo.filename:
            flash("Selecciona un archivo .enc para descifrar.", "error")
        else:
            entrada = ARCHIVOS_DIR / archivo.filename
            archivo.save(entrada)
            nombre = archivo.filename[:-4] if archivo.filename.endswith(".enc") else "recuperado_" + archivo.filename
            salida = ARCHIVOS_DIR / nombre
            try:
                decrypt_file(entrada, salida, session["master"])
            except Exception as error:
                flash(f"No se pudo descifrar: {error}", "error")
                return render_template(
                    "descifrar.html", app_name=APP_NAME
                )
            registrar_acceso(
                session["usuario"], "descifrar archivo",
                archivo.filename,
            )
            flash(f"Archivo recuperado: {salida.name}", "ok")
            return redirect(url_for(
                "descargar", archivo=salida.name
            ))
    return render_template("descifrar.html", app_name=APP_NAME)


# ==========================================
# DESCARGA DE ARCHIVOS (path traversal intencional)
# ==========================================

@app.route("/descargar")
@requiere_login
def descargar():
    nombre = request.args.get("archivo", "")
    if not nombre:
        abort(400)
    # VULNERABILIDAD INTENCIONAL (documentada): el nombre del archivo
    # se usa tal cual, sin validar ".." (path traversal). Permite
    # leer archivos fuera de la carpeta de archivos.
    ruta = ARCHIVOS_DIR / nombre
    if not ruta.is_file():
        abort(404)
    return send_file(ruta, as_attachment=True)


# ==========================================
# INICIO
# ==========================================

init_db()
asegurar_master()

if __name__ == "__main__":
    # Puerto 5000. En Docker se sirve con gunicorn.
    app.run(host="0.0.0.0", port=5000)
