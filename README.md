# SpecOps-Web 1.0.0

Panel web de **SpecOps-CLI** (proyecto del equipo, "Security Operations
CLI"), construido para la práctica de ciberseguridad: desplegar la web
en una máquina virtual con Docker y hacerle pentesting desde Kali.

> **Solo para laboratorio aislado.** Esta web tiene vulnerabilidades
> intencionales (ver `VULNERABILIDADES.md`). No exponerla a internet
> ni a ninguna red real.

## Qué hace

Es la versión web del menú del CLI:

- **Acceso** con la contraseña maestra (la misma del CLI).
- **Panel**: servicios del almacén y últimos accesos.
- **Almacén**: guardar y consultar credenciales cifradas (Fernet,
  con el módulo `auth_crypto.py` del equipo).
- **Buscar**: buscar servicios en el almacén.
- **Cifrar / Descifrar**: subir un archivo, cifrarlo o descifrarlo
  con la contraseña maestra (formato GAELCRYPT1) y descargarlo.

## Estructura

```
specops-web/
├── app.py                 # Aplicación Flask
├── modules/
│   └── auth_crypto.py     # Módulo del equipo (sin cambios)
├── templates/             # Páginas HTML
├── static/style.css       # Estilos
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── VULNERABILIDADES.md    # Solo para el equipo y el docente
```

## Arranque rápido (en la MV, con Docker)

```bash
docker compose up --build -d
```

La web queda en `http://<IP-de-la-MV>:5000`.

Contraseña maestra inicial: `SpecOps2026!` (cámbiala en
`docker-compose.yml` antes de levantar el laboratorio).

## Arranque sin Docker (pruebas locales)

```bash
python -m venv .venv
source .venv/bin/activate        # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

La web queda en `http://127.0.0.1:5000`.

## Guía completa

Ver el documento `Guia_SpecOps_Web_Docker_Pentesting.docx`:
despliegue en VirtualBox, Docker, pentesting desde Kali y
plantilla del reporte.
