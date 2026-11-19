import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


def validar_objetivo(host: str) -> str:
    """Valida si el host es una IP válida o resuelve su nombre de dominio."""
    host_limpio = host.strip()
    if not host_limpio:
        raise ValueError("El objetivo de escaneo no puede estar vacío.")

    try:
        ip_obj = ipaddress.ip_address(host_limpio)
        return str(ip_obj)
    except ValueError:
        pass

    try:
        return socket.gethostbyname(host_limpio)
    except socket.gaierror as exc:
        raise ValueError(f"No se pudo resolver el objetivo '{host_limpio}'.") from exc


def escanear_puerto(ip: str, puerto: int, timeout: float = 0.5) -> dict[str, Any] | None:
    """Sondea un puerto TCP e intenta capturar un banner básico si responde."""
    if not (1 <= puerto <= 65535):
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, puerto)) != 0:
            return None

        banner = ""
        try:
            sock.settimeout(0.3)
            data = sock.recv(512)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
        except OSError:
            banner = ""

        return {
            "puerto": puerto,
            "estado": "abierto",
            "banner": banner,
        }
    except OSError:
        return None
    finally:
        sock.close()


def escanear_puertos(
    ip: str,
    puertos: list[int],
    timeout: float = 0.5,
    max_hilos: int = 50,
) -> list[dict[str, Any]]:
    """Escanea una lista de puertos de forma concurrente."""
    puertos_abiertos: list[dict[str, Any]] = []
    if not puertos:
        return puertos_abiertos

    hilos = max(1, min(max_hilos, len(puertos)))
    with ThreadPoolExecutor(max_workers=hilos) as executor:
        futuros = {
            executor.submit(escanear_puerto, ip, puerto, timeout): puerto
            for puerto in puertos
        }
        for futuro in as_completed(futuros):
            hallazgo = futuro.result()
            if hallazgo:
                puertos_abiertos.append(hallazgo)

    puertos_abiertos.sort(key=lambda item: item["puerto"])
    return puertos_abiertos


def ejecutar_escaneo(
    objetivo: str,
    puertos: list[int] | None = None,
    timeout: float = 0.5,
    max_hilos: int = 50,
) -> dict[str, Any]:
    """Ejecuta el escaneo sobre el objetivo indicado y devuelve el resultado."""
    if puertos is None:
        puertos = [21, 22, 80, 443, 3000, 5000, 8000, 8080]

    inicio = time.perf_counter()
    ip_resuelta = validar_objetivo(objetivo)
    abiertos = escanear_puertos(ip_resuelta, puertos, timeout=timeout, max_hilos=max_hilos)
    duracion_seg = round(time.perf_counter() - inicio, 3)

    return {
        "objetivo_solicitado": objetivo,
        "ip_resuelta": ip_resuelta,
        "total_puertos_evaluados": len(puertos),
        "puertos_abiertos": abiertos,
        "duracion_segundos": duracion_seg,
    }


if __name__ == "__main__":
    resultado = ejecutar_escaneo("127.0.0.1", [22, 80, 443, 8000, 8080])
    print(resultado)
