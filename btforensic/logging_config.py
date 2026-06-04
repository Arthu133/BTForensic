from __future__ import annotations

import logging
import sys
from pathlib import Path

from .safe_redaction import PRIVACY_STRICT, redact_sensitive_text


class PrivacyLogFilter(logging.Filter):
    def __init__(self, privacy: str):
        super().__init__()
        self.privacy = privacy

    def filter(self, record: logging.LogRecord) -> bool:
        if self.privacy != PRIVACY_STRICT:
            return True
        record.msg = redact_sensitive_text(record.getMessage(), redact_paths=True)
        record.args = ()
        return True


def setup_logging(output_dir: Path | None = None, verbose: bool = False, privacy: str = PRIVACY_STRICT) -> logging.Logger:
    logger = logging.getLogger("BTForensic")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    console.addFilter(PrivacyLogFilter(privacy))

    logger.addHandler(console)
    if output_dir is not None:
        logs_dir = output_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(logs_dir / "BTForensic.log", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(PrivacyLogFilter(privacy))
        logger.addHandler(file_handler)
    return logger
