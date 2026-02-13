from __future__ import annotations

from security.runners.common import Finding, load_config, run_commands, write_stage_report


if __name__ == "__main__":
    config = load_config()
    execution = run_commands("sast", config.get("commands", {}).get("sast", []))

    findings: list[Finding] = []
    for entry in execution:
        if entry.get("status") == "failed":
            findings.append(
                Finding(
                    stage="sast",
                    severity="high",
                    title="SAST command failed",
                    details=entry.get("command", ""),
                )
            )

    path = write_stage_report("sast", findings=findings, status=execution)
    print(f"wrote {path}")
