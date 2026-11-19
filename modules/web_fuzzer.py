"""Comprueba la respuesta HTTP de una ruta conocida en una aplicación local."""

import argparse
import re
import sys
from urllib.parse import urlsplit

import requests


LOCAL_AUTHORITY = re.compile(r"(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?")
TIMEOUT_SECONDS = 5


def inspect_response(url: str) -> tuple[int, str]:
    """Consulta una ruta explícita y devuelve su estado y tipo de contenido."""
    if "\\" in url or "#" in url or any(char.isspace() or ord(char) < 32 for char in url):
        raise ValueError("Indica una URL sin espacios, caracteres de control ni fragmentos.")
    target = urlsplit(url)
    if target.scheme not in {"http", "https"} or not LOCAL_AUTHORITY.fullmatch(target.netloc):
        raise ValueError("Usa una URL HTTP o HTTPS en 127.0.0.1 o [::1].")
    if target.port == 0:
        raise ValueError("El puerto debe estar entre 1 y 65535.")

    with requests.Session() as session:
        session.trust_env = False
        with session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=False, stream=True) as response:
            media_type = response.headers.get("Content-Type", "").partition(";")[0].strip().lower()
            return response.status_code, media_type


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", metavar="URL", help="URL local de la ruta conocida")
    parser.add_argument("--estado", type=int, default=200, help="código HTTP esperado (por defecto, 200)")
    parser.add_argument("--tipo-contenido", help="tipo de contenido esperado, como application/json")
    args = parser.parse_args()
    if not 100 <= args.estado <= 599:
        parser.error("--estado debe estar entre 100 y 599.")
    expected_type = args.tipo_contenido.strip().lower() if args.tipo_contenido is not None else None
    if expected_type == "":
        parser.error("--tipo-contenido requiere un valor.")

    try:
        status, media_type = inspect_response(args.url)
    except (ValueError, requests.RequestException) as error:
        print(f"No se pudo consultar la ruta. {error}", file=sys.stderr)
        return 1

    print(f"Estado HTTP {status} · {media_type or 'tipo de contenido sin declarar'}")
    passed = True
    if status != args.estado:
        print(f"Se esperaba el estado HTTP {args.estado}.", file=sys.stderr)
        passed = False
    if expected_type is not None and media_type != expected_type:
        print(f"Se esperaba el tipo de contenido {expected_type}.", file=sys.stderr)
        passed = False
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
