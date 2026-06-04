from __future__ import annotations

import logging
from pathlib import Path


def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("BTForensic")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)

    file_handler = logging.FileHandler(logs_dir / "BTForensic.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger
