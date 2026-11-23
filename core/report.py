"""Generador de reportes forenses del Laboratorio BAS.

Uso desde la carpeta principal del proyecto:
    python -m core.report

Genera un reporte JSON con el estado de las evidencias recibidas,
la bitacora general y la cadena de custodia.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.logger import (
    AuditLogger,
    BASE_DIR,
    EVIDENCE_DIR,
    MANIFEST_DIR,
    CUSTODY_FILE,
)

REPORT_DIR = EVIDENCE_DIR / "reports"


def load_custody_records():
    """Carga los registros de custodia agrupados por ID de evidencia."""
    records = {}

    if not CUSTODY_FILE.exists():
        return records

    with CUSTODY_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            record = json.loads(line)
            evidence_id = record.get("evidence_id")
            if evidence_id:
                records[evidence_id] = record

    return records


def manifest_matches_custody(manifest, custody_record):
    """Comprueba que la ficha coincida con su registro encadenado de custodia."""
    if not custody_record:
        return False

    if manifest.get("custody_record_hash") != custody_record.get("record_hash"):
        return False

    fields_to_compare = (
        "evidence_id",
        "original_filename",
        "stored_file",
        "delivered_by",
        "received_by",
        "received_at_utc",
        "description",
        "sha256",
        "size_bytes",
        "status",
    )

    return all(
        manifest.get(field) == custody_record.get(field)
        for field in fields_to_compare
    )


def generate_forensic_report(actor="Mariana"):
    """Verifica las evidencias y genera un reporte JSON consolidado."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    auditor = AuditLogger(actor=actor)

    # Se valida la cadena antes de confiar en sus registros.
    custody_result = auditor.verify_custody_log()

    try:
        custody_records = load_custody_records() if custody_result.get("valid") else {}
    except (OSError, json.JSONDecodeError):
        custody_records = {}
        custody_result = {
            "valid": False,
            "records_checked": custody_result.get("records_checked", 0),
            "message": "No fue posible leer los registros de custodia."
        }

    evidence_results = []
    manifest_files = sorted(MANIFEST_DIR.glob("BAS-EVD-*.json"))

    for manifest_path in manifest_files:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            evidence_id = manifest["evidence_id"]
            custody_record = custody_records.get(evidence_id)

            custody_match = manifest_matches_custody(manifest, custody_record)
            file_result = auditor.verify_received_evidence(evidence_id)

            evidence_valid = (
                custody_result.get("valid", False)
                and custody_match
                and file_result.get("integrity_valid", False)
            )

            evidence_results.append({
                "evidence_id": evidence_id,
                "filename": manifest.get("original_filename"),
                "delivered_by": manifest.get("delivered_by"),
                "received_by": manifest.get("received_by"),
                "received_at_utc": manifest.get("received_at_utc"),
                "sha256": manifest.get("sha256"),
                "size_bytes": manifest.get("size_bytes"),
                "file_integrity_valid": file_result.get("integrity_valid", False),
                "manifest_matches_custody": custody_match,
                "integrity_valid": evidence_valid,
                "status": "VERIFIED" if evidence_valid else "REVIEW_REQUIRED",
            })

        except (OSError, ValueError, KeyError, TypeError) as error:
            evidence_results.append({
                "manifest": manifest_path.name,
                "integrity_valid": False,
                "status": "MANIFEST_OR_EVIDENCE_ERROR",
                "error": str(error),
            })

    total = len(evidence_results)
    verified = sum(1 for item in evidence_results if item.get("integrity_valid") is True)
    altered_or_errors = total - verified

    # Esta accion queda incluida en la verificacion final de la bitacora.
    auditor.log_action(
        action="FORENSIC_REPORT_GENERATED",
        description="Se genero un reporte forense del estado de las evidencias.",
        metadata={
            "total_evidence": total,
            "verified_evidence": verified,
            "review_required": altered_or_errors,
        },
    )

    audit_result = auditor.verify_log()

    generated_at = datetime.now(timezone.utc)
    report_id = f"BAS-REPORT-{generated_at:%Y%m%dT%H%M%SZ}"

    if total == 0:
        overall_status = "NO_EVIDENCE"
    elif (
        verified == total
        and custody_result.get("valid") is True
        and audit_result.get("valid") is True
    ):
        overall_status = "VERIFIED"
    else:
        overall_status = "REVIEW_REQUIRED"

    report = {
        "report_id": report_id,
        "generated_at_utc": generated_at.isoformat(),
        "generated_by": actor,
        "overall_status": overall_status,
        "summary": {
            "total_evidence": total,
            "verified_evidence": verified,
            "altered_or_unverified_evidence": altered_or_errors,
        },
        "audit_log_verification": audit_result,
        "custody_log_verification": custody_result,
        "evidence": evidence_results,
    }

    report_path = REPORT_DIR / f"{report_id}.json"
    report_path.write_text(
        json.dumps(report, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    return {"report_path": str(report_path.relative_to(BASE_DIR)), "report": report}


if __name__ == "__main__":
    result = generate_forensic_report(actor="Mariana")
    print(json.dumps(result, indent=4, ensure_ascii=False))
