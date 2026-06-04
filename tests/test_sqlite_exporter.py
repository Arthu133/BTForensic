import sqlite3
import tempfile
import unittest
from pathlib import Path

from btforensic.sqlite_exporter import copied_sqlite_connection, export_table, write_json


class SQLiteExporterTest(unittest.TestCase):
    def test_invalid_utf8_cookie_bytes_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "Cookies"
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value TEXT)")
            conn.execute(
                "INSERT INTO cookies VALUES (?, ?, CAST(x'763230fffe41' AS TEXT))",
                (".linkedin.com", "li_at"),
            )
            conn.commit()
            conn.close()

            with copied_sqlite_connection(db_path) as copied:
                rows = export_table(copied, "cookies")

            self.assertEqual(rows[0]["host_key"], ".linkedin.com")
            self.assertIsInstance(rows[0]["encrypted_value"], bytes)

    def test_write_json_redacts_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            write_json(out, {"encrypted_value": b"secret-bytes"})
            text = out.read_text(encoding="utf-8")
            self.assertIn('"redacted_bytes": true', text)
            self.assertIn('"sha256"', text)
            self.assertNotIn("secret-bytes", text)


if __name__ == "__main__":
    unittest.main()
