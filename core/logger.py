"""
BAS - Bitacora y Trazabilidad de Integridad
Archivo: core/logger.py
Responsable: Mariana

Registra acciones, calcula hashes SHA-256 y verifica la integridad
 de los archivos de evidencia, la bitacora y la cadena de custodia.
"""

import hashlib
import json
import logging
import shutil
import threading
import uuid

from datetime import datetime, timezone
from pathlib import Path


# ==========================================================
# CONFIGURACION GENERAL
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"
LOG_DIR = EVIDENCE_DIR / "logs"
MANIFEST_DIR = EVIDENCE_DIR / "manifests"
RECEIVED_DIR = EVIDENCE_DIR / "received"

AUDIT_FILE = LOG_DIR / "audit.jsonl"
CUSTODY_FILE = LOG_DIR / "custody.jsonl"

GENESIS_HASH = "0" * 64
_lock = threading.Lock()


# ==========================================================
# INICIALIZACION
# ==========================================================

def initialize_logger():
    """Crea las carpetas necesarias y configura el registro local."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )


# ==========================================================
# CALCULO SHA-256
# ==========================================================

def calculate_sha256(file_path):
    """Calcula SHA-256 leyendo el archivo por bloques."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"No existe el archivo: {path}")

    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


# ==========================================================
# NUCLEO DE AUDITORIA
# ==========================================================

class AuditLogger:
    """Nucleo de auditoria y cadena de custodia del laboratorio BAS."""

    def __init__(self, actor="Sistema BAS"):
        initialize_logger()
        self.actor = actor

    @staticmethod
    def _canonical_json(data):
        """Serializa datos de forma consistente para calcular hashes."""
        return json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        )

    # ------------------------------------------------------
    # BITACORA GENERAL
    # ------------------------------------------------------

    def _get_last_hash(self):
        """Devuelve el hash del ultimo evento o el hash inicial."""
        if not AUDIT_FILE.exists():
            return GENESIS_HASH

        last_hash = GENESIS_HASH

        with AUDIT_FILE.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                    last_hash = event["event_hash"]
                except (json.JSONDecodeError, KeyError) as error:
                    raise ValueError(
                        f"No se pudo leer el evento de la linea {line_number}: {error}"
                    ) from error

        return last_hash

    def log_action(self, action, description, metadata=None, actor=None):
        """
        Registra una accion en la bitacora encadenada.

        No registrar contrasenas, tokens, cookies ni datos personales
        reales en description o metadata.
        """
        with _lock:
            previous_hash = self._get_last_hash()

            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": actor or self.actor,
                "action": action,
                "description": description,
                "metadata": metadata or {},
                "previous_hash": previous_hash
            }

            event_hash = hashlib.sha256(
                self._canonical_json(event).encode("utf-8")
            ).hexdigest()

            stored_event = {**event, "event_hash": event_hash}

            with AUDIT_FILE.open("a", encoding="utf-8") as file:
                file.write(self._canonical_json(stored_event) + "\n")

            logging.info(
                "Accion registrada: %s | Responsable: %s",
                action,
                actor or self.actor
            )

            return event_hash

    # ------------------------------------------------------
    # REGISTRO SIMPLE DE EVIDENCIAS (FUNCION ORIGINAL)
    # ------------------------------------------------------

    def register_evidence(self, file_path, description):
        """Calcula y registra la huella SHA-256 de un archivo."""
        path = Path(file_path).resolve()

        if not path.is_file():
            raise FileNotFoundError(f"No se encontro la evidencia: {path}")

        evidence_data = {
            "filename": path.name,
            "sha256": calculate_sha256(path),
            "size_bytes": path.stat().st_size
        }

        self.log_action(
            action="EVIDENCE_REGISTERED",
            description=description,
            metadata=evidence_data
        )

        manifest_path = MANIFEST_DIR / f"{path.name}.sha256.json"
        manifest_path.write_text(
            json.dumps(evidence_data, indent=4, ensure_ascii=False),
            encoding="utf-8"
        )

        return evidence_data

    # ------------------------------------------------------
    # CADENA DE CUSTODIA
    # ------------------------------------------------------

    def _get_last_custody_hash(self):
        """Obtiene el hash del ultimo registro de custodia."""
        if not CUSTODY_FILE.exists():
            return GENESIS_HASH

        last_hash = GENESIS_HASH

        with CUSTODY_FILE.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                    last_hash = record["record_hash"]
                except (json.JSONDecodeError, KeyError) as error:
                    raise ValueError(
                        f"No se pudo leer el registro de custodia de la linea {line_number}: {error}"
                    ) from error

        return last_hash

    def _append_custody_record(self, record):
        """Agrega un registro encadenado al archivo de custodia."""
        with _lock:
            previous_hash = self._get_last_custody_hash()

            data = {
                **record,
                "previous_hash": previous_hash
            }

            record_hash = hashlib.sha256(
                self._canonical_json(data).encode("utf-8")
            ).hexdigest()

            stored_record = {
                **data,
                "record_hash": record_hash
            }

            with CUSTODY_FILE.open("a", encoding="utf-8") as file:
                file.write(self._canonical_json(stored_record) + "\n")

        return record_hash

    def receive_evidence(self, file_path, delivered_by, description):
        """
        Recibe una evidencia desde evidence/incoming/<integrante>/.

        - Genera un identificador unico.
        - Calcula el SHA-256 del archivo recibido.
        - Copia el archivo a evidence/received/ sin mover el original.
        - Comprueba que el original y la copia coincidan.
        - Registra quien entrega y quien recibe.
        - Crea un manifiesto JSON y un registro encadenado de custodia.

        delivered_by es el nombre declarado del integrante; esta version
        no autentica digitalmente la identidad de quien entrega el archivo.
        """
        source = Path(file_path).resolve()

        if not source.is_file():
            raise FileNotFoundError(f"No se encontro el archivo: {source}")

        incoming_root = (EVIDENCE_DIR / "incoming").resolve()

        try:
            source.relative_to(incoming_root)
        except ValueError as error:
            raise ValueError(
                "La evidencia debe estar dentro de evidence/incoming/<integrante>/."
            ) from error

        delivered_by = str(delivered_by).strip()
        description = str(description).strip()

        if not delivered_by:
            raise ValueError("Debes indicar quien entrega la evidencia.")

        if not description:
            raise ValueError("Debes agregar una descripcion de la evidencia.")

        if source.parent.name.casefold() != delivered_by.casefold():
            raise ValueError(
                "El nombre del responsable debe coincidir con la carpeta de entrega."
            )

        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

        received_at = datetime.now(timezone.utc)
        evidence_id = (
            f"BAS-EVD-{received_at:%Y%m%d}-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

        # Calcular el hash antes de copiar el archivo.
        original_hash_before = calculate_sha256(source)
        original_size = source.stat().st_size

        destination = RECEIVED_DIR / f"{evidence_id}_{source.name}"

        # Se conserva el original y se trabaja con una copia.
        shutil.copy2(source, destination)

        # Comprobar que el original no cambio y que la copia es identica.
        original_hash_after = calculate_sha256(source)
        received_hash = calculate_sha256(destination)

        if not (
            original_hash_before == original_hash_after == received_hash
        ):
            destination.unlink(missing_ok=True)
            raise RuntimeError(
                "La evidencia cambio durante la recepcion o la copia no coincide."
            )

        evidence_data = {
            "evidence_id": evidence_id,
            "original_filename": source.name,
            "stored_file": destination.relative_to(BASE_DIR).as_posix(),
            "delivered_by": delivered_by,
            "received_by": self.actor,
            "received_at_utc": received_at.isoformat(),
            "description": description,
            "sha256": original_hash_before,
            "size_bytes": original_size,
            "status": "RECEIVED_VERIFIED"
        }

        # Registrar la recepcion tambien en la bitacora general.
        audit_hash = self.log_action(
            action="EVIDENCE_RECEIVED",
            description=f"Recepcion de evidencia {evidence_id}",
            metadata=evidence_data
        )

        # Crear el registro encadenado de cadena de custodia.
        custody_hash = self._append_custody_record({
            **evidence_data,
            "audit_event_hash": audit_hash
        })

        manifest = {
            **evidence_data,
            "audit_event_hash": audit_hash,
            "custody_record_hash": custody_hash
        }

        manifest_path = MANIFEST_DIR / f"{evidence_id}.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=4, ensure_ascii=False),
            encoding="utf-8"
        )

        logging.info(
            "Evidencia recibida: %s | Entrega: %s | Recibe: %s",
            evidence_id,
            delivered_by,
            self.actor
        )

        return manifest

    def verify_received_evidence(self, evidence_id):
        """Verifica que la copia recibida coincida con el hash del manifiesto."""
        if Path(evidence_id).name != evidence_id or not evidence_id.startswith("BAS-EVD-"):
            raise ValueError("Identificador de evidencia no valido.")

        manifest_path = MANIFEST_DIR / f"{evidence_id}.json"

        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"No existe el manifiesto para la evidencia {evidence_id}."
            )

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        stored_path = (BASE_DIR / manifest["stored_file"]).resolve()

        try:
            stored_path.relative_to(RECEIVED_DIR.resolve())
        except ValueError as error:
            raise ValueError(
                "La ruta registrada no pertenece a evidence/received/."
            ) from error

        result = self.verify_file(stored_path, manifest["sha256"])

        self.log_action(
            action="EVIDENCE_INTEGRITY_CHECK",
            description=f"Verificacion de evidencia {evidence_id}",
            metadata={
                "evidence_id": evidence_id,
                "integrity_valid": result["integrity_valid"],
                "expected_hash": result["expected_hash"],
                "current_hash": result["current_hash"]
            }
        )

        return result

    def verify_file(self, file_path, expected_hash):
        """Compara el hash actual de un archivo con el hash esperado."""
        current_hash = calculate_sha256(file_path)

        return {
            "file": str(file_path),
            "expected_hash": expected_hash,
            "current_hash": current_hash,
            "integrity_valid": current_hash == expected_hash
        }

    # ------------------------------------------------------
    # VERIFICACION DE BITACORA GENERAL
    # ------------------------------------------------------

    def verify_log(self):
        """Verifica hashes de eventos y continuidad de la bitacora."""
        if not AUDIT_FILE.exists():
            return {
                "valid": True,
                "events_checked": 0,
                "message": "No existen eventos registrados."
            }

        previous_hash = GENESIS_HASH
        events_checked = 0

        with AUDIT_FILE.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    stored_event = json.loads(line)
                    recorded_hash = stored_event["event_hash"]

                    event_data = {
                        key: value
                        for key, value in stored_event.items()
                        if key != "event_hash"
                    }

                    if event_data.get("previous_hash") != previous_hash:
                        raise ValueError(
                            "La cadena de hashes fue interrumpida."
                        )

                    calculated_hash = hashlib.sha256(
                        self._canonical_json(event_data).encode("utf-8")
                    ).hexdigest()

                    if calculated_hash != recorded_hash:
                        raise ValueError(
                            "El contenido del evento fue modificado."
                        )

                    previous_hash = recorded_hash
                    events_checked += 1

                except (json.JSONDecodeError, KeyError, ValueError) as error:
                    return {
                        "valid": False,
                        "events_checked": events_checked,
                        "error": str(error),
                        "line": line_number
                    }

        return {
            "valid": True,
            "events_checked": events_checked,
            "last_hash": previous_hash,
            "message": "Integridad de la bitacora verificada."
        }

    # ------------------------------------------------------
    # VERIFICACION DE CADENA DE CUSTODIA
    # ------------------------------------------------------

    def verify_custody_log(self):
        """Verifica hashes y continuidad de todos los registros de custodia."""
        if not CUSTODY_FILE.exists():
            return {
                "valid": True,
                "records_checked": 0,
                "message": "No existen registros de custodia."
            }

        previous_hash = GENESIS_HASH
        records_checked = 0

        with CUSTODY_FILE.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    stored_record = json.loads(line)
                    recorded_hash = stored_record["record_hash"]

                    record_data = {
                        key: value
                        for key, value in stored_record.items()
                        if key != "record_hash"
                    }

                    if record_data.get("previous_hash") != previous_hash:
                        raise ValueError(
                            "Se rompio la continuidad de la cadena de custodia."
                        )

                    calculated_hash = hashlib.sha256(
                        self._canonical_json(record_data).encode("utf-8")
                    ).hexdigest()

                    if calculated_hash != recorded_hash:
                        raise ValueError(
                            "Un registro de custodia fue modificado."
                        )

                    previous_hash = recorded_hash
                    records_checked += 1

                except (json.JSONDecodeError, KeyError, ValueError) as error:
                    return {
                        "valid": False,
                        "records_checked": records_checked,
                        "error": str(error),
                        "line": line_number
                    }

        return {
            "valid": True,
            "records_checked": records_checked,
            "last_hash": previous_hash,
            "message": "Cadena de custodia verificada."
        }


# ==========================================================
# PRUEBA DIRECTA DEL MODULO
# ==========================================================

if __name__ == "__main__":
    auditor = AuditLogger(actor="Mariana")
    auditor.log_action(
        action="LOGGER_TEST",
        description="Prueba de funcionamiento del modulo BAS."
    )

    print("\n--- VERIFICACION DE BITACORA ---")
    print(json.dumps(auditor.verify_log(), indent=4, ensure_ascii=False))

    print("\n--- VERIFICACION DE CADENA DE CUSTODIA ---")
    print(json.dumps(auditor.verify_custody_log(), indent=4, ensure_ascii=False))
