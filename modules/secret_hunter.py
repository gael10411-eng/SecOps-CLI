"""Detecta posibles secretos en archivos de texto y código Python local."""

import argparse
import ast
from collections.abc import Iterator
import os
from pathlib import Path
import re
import stat


MAX_FILE_BYTES = 1024 * 1024
IGNORED_DIRECTORIES = {"__pycache__", "build", "coverage", "dist", "node_modules", "target", "venv"}
SIGNATURES = (
    ("marcador de clave privada", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    (
        "posible token JWT",
        re.compile(r"(?<![\w-])eyJ[\w-]{4,}\.eyJ[\w-]{4,}\.[\w-]{8,}(?![\w-])", re.ASCII),
    ),
)
CREDENTIAL_NAMES = (
    "secret_access_key", "client_secret", "clientsecret", "jwt_secret", "private_key",
    "privatekey", "secret_key", "secretkey", "access_key", "api_key", "apikey",
    "access_token", "accesstoken", "refresh_token", "auth_token", "api_token",
    "password", "passwd", "passphrase", "token",
)
CAMEL_CASE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
ASSIGNMENT = re.compile(
    r"""^\s*(?:export\s+)?(?P<quote>["']?)(?P<name>[a-z_][a-z0-9_-]*)(?P=quote)\s*[:=]\s*(?P<value>.*)$""",
    re.ASCII | re.IGNORECASE,
)
VALUE = re.compile(r"""(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^#,\s"']+))""")
REFERENCE = re.compile(r"\$(?:[a-z_]\w*|\{[^}]+\})|<[^>]+>", re.IGNORECASE)
PLACEHOLDERS = {
    "changeme", "example", "none", "null", "placeholder", "replace_me", "todo",
    "your_api_key_here", "your_password_here", "your_token_here", "|", ">", "|-", ">-",
}

Literal = tuple[str, str, int, int]
Finding = tuple[int, str]


def analyze(path: Path) -> list[str]:
    """Devuelve la ubicación y el tipo de cada posible secreto."""
    if _is_link(path.lstat()) or not path.is_dir():
        raise ValueError("Indica un directorio local sin enlaces simbólicos.")

    findings = []
    for folder, directories, filenames in os.walk(path, onerror=_raise_walk_error):
        directory = Path(folder)
        directories[:] = sorted(
            name for name in directories
            if not name.startswith(".")
            and name.casefold() not in IGNORED_DIRECTORIES
            and not _is_link((directory / name).lstat())
        )
        for filename in sorted(filenames):
            candidate = directory / filename
            metadata = candidate.lstat()
            if _is_link(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
                continue

            with candidate.open("rb") as source:
                content = source.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES or b"\0" in content:
                continue
            try:
                source = content.decode("utf-8-sig")
            except UnicodeDecodeError:
                continue

            relative = candidate.relative_to(path).as_posix()
            for number, kind in _find_in_file(source, candidate.suffix.lower()):
                findings.append(f"{relative!r}, línea {number}: {kind}.")

    return findings


def _find_in_file(source: str, suffix: str) -> list[Finding]:
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    lines = source.split("\n")
    signatures = {
        (number, kind)
        for number, line in enumerate(lines, start=1)
        for kind, pattern in SIGNATURES
        if pattern.search(line)
    }
    literals = _text_literals(lines)
    if suffix in {".py", ".pyw"}:
        try:
            tree = ast.parse(source)
        except (SyntaxError, RecursionError):
            pass  # La revisión de texto también sirve para código en edición.
        else:
            literals = (
                (name, value.value, value.lineno, value.end_lineno or value.lineno)
                for name, value in _python_bindings(tree)
                if isinstance(value, ast.Constant) and isinstance(value.value, str)
            )

    findings = signatures.copy()
    for name, value, start, end in literals:
        name = CAMEL_CASE.sub("_", name).lower().replace("-", "_")
        category = next(
            (item for item in CREDENTIAL_NAMES if name == item or name.endswith("_" + item)),
            None,
        )
        if category is None:
            continue
        value = value.strip()
        if not value or value.lower() in PLACEHOLDERS or REFERENCE.fullmatch(value):
            continue

        kind = next((label for label, pattern in SIGNATURES if pattern.search(value)), None)
        if kind is None:
            findings.add((start, f"posible credencial en {category}"))
        elif not any((number, kind) in signatures for number in range(start, end + 1)):
            findings.add((start, kind))
    return sorted(findings)


def _text_literals(lines: list[str]) -> Iterator[Literal]:
    for number, line in enumerate(lines, start=1):
        assignment = ASSIGNMENT.match(line)
        if assignment is None:
            continue
        raw_value = assignment["value"]
        if raw_value.startswith(("os.environ", "os.getenv(")):
            continue
        match = VALUE.match(raw_value)
        if match is not None:
            value = next(group for group in match.groups() if group is not None)
            yield assignment["name"], value, number, number


def _python_bindings(tree: ast.AST) -> Iterator[tuple[str, ast.expr]]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    yield target.id, node.value
                elif isinstance(target, ast.Attribute):
                    yield target.attr, node.value
                elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                    if isinstance(target.slice.value, str):
                        yield target.slice.value, node.value
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    yield key.value, value
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield node.arg, node.value
        elif isinstance(node, ast.arguments):
            positional = node.posonlyargs + node.args
            for argument, value in zip(reversed(positional), reversed(node.defaults)):
                yield argument.arg, value
            for argument, value in zip(node.kwonlyargs, node.kw_defaults):
                if value is not None:
                    yield argument.arg, value


def _is_link(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _raise_walk_error(error: OSError) -> None:
    raise error


def main() -> int:
    parser = argparse.ArgumentParser(description="Audita secretos en un directorio local.")
    parser.add_argument("directory", type=Path, metavar="DIRECTORIO", help="directorio que se va a revisar")
    args = parser.parse_args()

    try:
        findings = analyze(args.directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error al revisar el directorio. {error}\n")

    if not findings:
        print("Sin hallazgos.")
    for finding in findings:
        print(f"- {finding}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
