# Vulnerabilidades intencionales de SpecOps-Web

Este documento es SOLO para el equipo y el docente. Describe las
vulnerabilidades que se introdujeron A PROPÓSITO en la web para la
práctica de pentesting. No forma parte de la web ni debe publicarse
con ella.

Regla del laboratorio: todo el pentesting se hace en red aislada
(VirtualBox, red solo-anfitrión), contra esta web y nada más.

## 1. Inyección SQL (SQLi) — Crítica
- **Dónde:** `app.py`, ruta `/buscar` (parámetro `q`).
- **Cómo:** la consulta se construye concatenando la entrada:
  `SELECT servicio, usuario FROM indice WHERE servicio LIKE '%{q}%'`.
- **Qué permite:** con `UNION SELECT` se puede leer la tabla
  `usuarios` (por ejemplo, `' UNION SELECT usuario, password FROM usuarios --`),
  porque la búsqueda y los usuarios viven en la misma base SQLite.
- **Cómo se corrige:** consultas parametrizadas (`?` en sqlite3),
  nunca concatenar la entrada del usuario.

## 2. XSS reflejado — Alta
- **Dónde:** `templates/buscar.html`, el término buscado se muestra
  con `{{ q|safe }}` (sin escapar HTML).
- **Qué permite:** un enlace con un `q` malicioso ejecuta JavaScript
  en el navegador de quien lo abre (por ejemplo, robo de la cookie
  de sesión, que además no tiene HttpOnly).
- **Cómo se corrige:** quitar `|safe` y dejar que Jinja escape
  el texto por defecto.

## 3. Path traversal en descarga de archivos — Alta
- **Dónde:** `app.py`, ruta `/descargar` (parámetro `archivo`).
- **Cómo:** el nombre se usa tal cual para construir la ruta
  (`ARCHIVOS_DIR / nombre`), sin validar `..`.
- **Qué permite:** leer archivos fuera de la carpeta de archivos,
  por ejemplo `../../master.hash`, `../../specops.db` o
  `../../../../etc/passwd` (según el sistema).
- **Cómo se corrige:** validar el nombre (lista blanca de caracteres)
  y comprobar que la ruta resuelta sigue dentro de `ARCHIVOS_DIR`.

## 4. Credenciales por defecto — Alta
- **Dónde:** `docker-compose.yml` / `.env.example` y `app.py`
  (`MASTER_PASSWORD_INICIAL`).
- **Cómo:** la contraseña maestra inicial es `SpecOps2026!` y está
  documentada; además la tabla `usuarios` trae `admin / admin123`
  en texto plano.
- **Qué permite:** entrar al panel sin atacar nada, solo con
  conocer la contraseña de por defecto.
- **Cómo se corrige:** obligar a cambiar la contraseña en el primer
  inicio y no incluir usuarios de prueba en producción.

## 5. Contraseñas en texto plano en la base de datos — Media
- **Dónde:** `app.py`, función `init_db()`, tabla `usuarios`.
- **Cómo:** las contraseñas de `admin` y `operador` se guardan
  sin hash. (El almacén de credenciales del CLI sí usa cifrado
  Fernet; esta tabla es solo de la web.)
- **Qué permite:** quien lea `specops.db` (por ejemplo, con la
  vulnerabilidad 3 o la 1) obtiene las contraseñas directamente.
- **Cómo se corrige:** guardar hashes (por ejemplo, con el mismo
  `hash_password` de `auth_crypto.py`).

## 6. Sesión débil — Media
- **Dónde:** `app.py` (clave secreta y datos de sesión).
- **Cómo:**
  - `SECRET_KEY` es fija y débil (`specops-clave-secreta`), así que
    cualquiera puede firmar sus propias cookies de sesión.
  - La contraseña maestra se guarda en la sesión (`session["master"]`),
    y la cookie de Flask solo va firmada, no cifrada: su contenido
    se lee decodificando base64.
  - No hay tokens CSRF en los formularios.
- **Qué permite:** falsificar sesiones, leer la contraseña maestra
  de la cookie y enviar formularios desde otro sitio.
- **Cómo se corrige:** clave secreta larga y aleatoria (variable de
  entorno, nunca en el código), no guardar la contraseña maestra en
  la sesión, cookies con `HttpOnly` y `Secure`, y tokens CSRF
  (Flask-WTF).

## 7. Modo depuración activo (DEBUG=True) — Media
- **Dónde:** `app.py` (`app.config["DEBUG"]`) y `docker-compose.yml`.
- **Cómo:** con DEBUG activo, un error muestra la traza completa
  (rutas, variables, fragmentos de código) y el depurador de
  Werkzeug puede permitir ejecutar código.
- **Cómo se corrige:** `DEBUG=False` fuera del laboratorio.

## Resumen para el reporte

| # | Vulnerabilidad | Severidad | Ruta / archivo |
|---|----------------|-----------|----------------|
| 1 | Inyección SQL | Crítica | `/buscar` — app.py |
| 2 | XSS reflejado | Alta | `/buscar` — buscar.html |
| 3 | Path traversal | Alta | `/descargar` — app.py |
| 4 | Credenciales por defecto | Alta | docker-compose.yml / init_db |
| 5 | Contraseñas en texto plano | Media | specops.db — init_db |
| 6 | Sesión débil | Media | app.py (SECRET_KEY, session) |
| 7 | Modo depuración activo | Media | app.py / docker-compose.yml |
