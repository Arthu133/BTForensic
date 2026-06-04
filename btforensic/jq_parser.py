from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path


def jq_available() -> bool:
    return shutil.which("jq") is not None


def normalize_json_file(input_path: Path, output_path: Path, logger: logging.Logger | None = None):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if jq_available():
        try:
            with output_path.open("w", encoding="utf-8") as out:
                subprocess.run(["jq", ".", str(input_path)], check=True, stdout=out, text=True)
            return json.loads(output_path.read_text(encoding="utf-8"))
        except Exception as exc:
            if logger:
                logger.warning("jq failed for %s, using Python fallback: %s", input_path, exc)
    elif logger:
        logger.warning("jq not found; using Python JSON fallback")

    with input_path.open("r", encoding="utf-8-sig") as src:
        data = json.load(src)
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return data
