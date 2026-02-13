from __future__ import annotations

from security.runners.common import Finding, load_config, run_commands, write_stage_report


if __name__ == "__main__":
    config = load_config()
    execution = run_commands("api_fuzz", config.get("commands", {}).get("api_fuzz", []))

    findings: list[Finding] = []
    for entry in execution:
        if entry.get("status") == "failed":
            findings.append(
                Finding(
                    stage="api_fuzz",
                    severity="high",
                    title="API fuzz command failed",
                    details=entry.get("command", ""),
                )
            )

    path = write_stage_report("api_fuzz", findings=findings, status=execution)
    print(f"wrote {path}")
