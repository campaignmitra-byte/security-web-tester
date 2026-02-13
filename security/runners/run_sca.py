from __future__ import annotations

from security.runners.common import Finding, load_config, run_commands, write_stage_report


if __name__ == "__main__":
    config = load_config()
    execution = run_commands("sca", config.get("commands", {}).get("sca", []))

    findings: list[Finding] = []
    for entry in execution:
        if entry.get("status") == "failed":
            findings.append(
                Finding(
                    stage="sca",
                    severity="high",
                    title="SCA command failed",
                    details=entry.get("command", ""),
                )
            )

    path = write_stage_report("sca", findings=findings, status=execution)
    print(f"wrote {path}")
