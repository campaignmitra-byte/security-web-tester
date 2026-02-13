from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
SECURITY_DIR = ROOT / "security"
REPORTS_DIR = SECURITY_DIR / "reports"
CONFIG_PATH = SECURITY_DIR / "config.json"


@dataclass
class Finding:
    stage: str
    severity: str
    title: str
    details: str = ""


def load_config() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_reports_dir() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def command_exists(command: str) -> bool:
    binary = command.strip().split()[0]
    return shutil.which(binary) is not None


def run_commands(stage: str, commands: Iterable[str]) -> list[dict]:
    """Run configured commands, recording execution status entries."""
    ensure_reports_dir()
    status_entries: list[dict] = []

    for command in commands:
        if not command_exists(command):
            status_entries.append(
                {
                    "stage": stage,
                    "status": "warning",
                    "command": command,
                    "message": "command not found; stage output may be incomplete",
                }
            )
            continue

        result = subprocess.run(
            command,
            shell=True,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        status_entries.append(
            {
                "stage": stage,
                "status": "passed" if result.returncode == 0 else "failed",
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout[-2000:],
                "stderr": result.stderr[-2000:],
            }
        )

    return status_entries


def write_stage_report(stage: str, findings: list[Finding], status: list[dict]) -> Path:
    ensure_reports_dir()
    path = REPORTS_DIR / f"{stage}.json"
    payload = {
        "stage": stage,
        "findings": [f.__dict__ for f in findings],
        "execution": status,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_default_no_findings(stage: str, message: str) -> Path:
    return write_stage_report(
        stage,
        findings=[],
        status=[{"stage": stage, "status": "warning", "message": message}],
    )
