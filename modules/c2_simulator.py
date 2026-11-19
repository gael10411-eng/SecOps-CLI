"""Simulación local de detección de egresos con eventos sintéticos."""

from dataclasses import dataclass
import sys


THRESHOLD_BYTES = 1024 * 1024


@dataclass(frozen=True)
class DemoEvent:
    direction: str
    scope: str
    size_bytes: int
    expected_alert: bool


DEMO_EVENTS = (
    DemoEvent("salida", "interno", 2 * THRESHOLD_BYTES, expected_alert=False),
    DemoEvent("entrada", "externo", 2 * THRESHOLD_BYTES, expected_alert=False),
    DemoEvent("salida", "externo", THRESHOLD_BYTES - 1, expected_alert=False),
    DemoEvent("salida", "externo", THRESHOLD_BYTES, expected_alert=True),
)


def run() -> int:
    """Ejecuta el ejercicio y verifica qué eventos generan una alerta."""
    print("Simulación de detección de egresos con datos sintéticos")
    results_match = True
    for index, event in enumerate(DEMO_EVENTS, start=1):
        actual_alert = (
            event.direction == "salida"
            and event.scope == "externo"
            and event.size_bytes >= THRESHOLD_BYTES
        )
        actual = "alerta" if actual_alert else "sin alerta"
        expected = "alerta" if event.expected_alert else "sin alerta"
        print(
            f"Evento {index} · {event.direction} · {event.scope} · {event.size_bytes} bytes"
            f" · esperado {expected} · detectado {actual}"
        )
        if actual_alert != event.expected_alert:
            results_match = False

    if not results_match:
        print("Las alertas no coinciden con los resultados esperados.", file=sys.stderr)
        return 1

    print("Validación correcta. Las alertas coinciden con los resultados esperados.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
