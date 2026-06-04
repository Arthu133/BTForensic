from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


BINARY_COLUMNS = {
    "encrypted_value",
    "key",
    "value_blob",
}


def copy_sqlite_to_temp(db_path: Path) -> tuple[tempfile.TemporaryDirectory, Path]:
    temp_dir = tempfile.TemporaryDirectory(prefix="btforensic_sqlite_")
    dest = Path(temp_dir.name) / db_path.name
    shutil.copy2(db_path, dest)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{db_path}{suffix}")
        if sidecar.exists():
            shutil.copy2(sidecar, Path(f"{dest}{suffix}"))
    return temp_dir, dest


@contextmanager
def copied_sqlite_connection(db_path: Path) -> Iterator[sqlite3.Connection]:
    temp_dir, copied = copy_sqlite_to_temp(db_path)
    try:
        conn = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.text_factory = bytes
        try:
            yield conn
        finally:
            conn.close()
    finally:
        temp_dir.cleanup()


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def get_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    if not table_exists(conn, table):
        return []
    return [
        _decode_sqlite_value("name", row["name"])
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    ]


def _decode_sqlite_value(column: str, value):
    if not isinstance(value, bytes):
        return value
    if column.lower() in BINARY_COLUMNS:
        return value
    return value.decode("utf-8", errors="replace")


def rows_to_dicts(rows) -> list[dict]:
    return [
        {key: _decode_sqlite_value(key, row[key]) for key in row.keys()}
        for row in rows
    ]


def export_table(conn: sqlite3.Connection, table: str, limit: int | None = None) -> list[dict]:
    if not table_exists(conn, table):
        return []
    sql = f"SELECT * FROM {table}"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return rows_to_dicts(conn.execute(sql).fetchall())


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(data), indent=2, ensure_ascii=False), encoding="utf-8")


def _json_safe(value):
    if isinstance(value, bytes):
        return {
            "redacted_bytes": True,
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    return value
