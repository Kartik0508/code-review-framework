import asyncio
import json
import os
from typing import Optional

from loguru import logger

from backend.scanners.base import BaseScanner, IssueData, OWASP_MAPPING, REMEDIATION_TEMPLATES, ScanOutput

DEFAULT_RULES = ["p/owasp-top-ten", "p/python", "p/javascript"]
CUSTOM_RULES_PATH = "/semgrep-rules"

SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "CRITICAL",
}


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    async def scan(self, repo_path: str, project_id: str, scan_id: str,
                   rules: Optional[list[str]] = None, **kwargs) -> ScanOutput:
        configs = list(rules) if rules else list(DEFAULT_RULES)

        # Add custom rules if the directory exists
        if os.path.isdir(CUSTOM_RULES_PATH):
            configs.append(CUSTOM_RULES_PATH)

        # Use local path if it's a directory; skip remote git URLs for semgrep
        scan_target = repo_path if os.path.isdir(repo_path) else "."

        cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore"]
        for cfg in configs:
            cmd += ["--config", cfg]
        cmd.append(scan_target)

        logger.info(f"Running semgrep: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            return ScanOutput(scanner=self.name, status="failed", error="Semgrep timed out after 5 minutes")
        except FileNotFoundError:
            return ScanOutput(scanner=self.name, status="failed", error="semgrep binary not found")

        if proc.returncode not in (0, 1):  # 1 = findings found, which is OK
            err = stderr.decode(errors="replace")[:2000]
            return ScanOutput(scanner=self.name, status="failed", error=f"Semgrep error (rc={proc.returncode}): {err}")

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            return ScanOutput(scanner=self.name, status="failed", error=f"Failed to parse semgrep output: {exc}")

        issue_data: list[IssueData] = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            raw_sev = extra.get("severity", "WARNING")
            severity = SEMGREP_SEVERITY_MAP.get(raw_sev.upper(), "MEDIUM")

            # CWE and OWASP from metadata
            cwe_raw = metadata.get("cwe", [])
            if isinstance(cwe_raw, list):
                cwe_id = cwe_raw[0] if cwe_raw else None
            else:
                cwe_id = cwe_raw or None

            owasp_raw = metadata.get("owasp", [])
            if isinstance(owasp_raw, list):
                owasp_category = owasp_raw[0] if owasp_raw else self.get_owasp(cwe_id)
            else:
                owasp_category = owasp_raw or self.get_owasp(cwe_id)

            # Remediation from references or templates
            references = metadata.get("references", [])
            remediation = metadata.get("fix", None)
            if not remediation:
                for key, template in REMEDIATION_TEMPLATES.items():
                    if key in result.get("check_id", "").lower():
                        remediation = template
                        break

            issue_data.append(IssueData(
                rule_id=result.get("check_id", "unknown"),
                severity=severity,
                title=extra.get("message", result.get("check_id", "Semgrep finding")),
                description=extra.get("message", ""),
                file_path=result.get("path"),
                line_start=result.get("start", {}).get("line"),
                line_end=result.get("end", {}).get("line"),
                cwe_id=str(cwe_id) if cwe_id else None,
                owasp_category=owasp_category,
                remediation=remediation,
            ))

        output = ScanOutput(scanner=self.name, status="completed", issues=issue_data)
        output.compute_summary()
        logger.info(f"Semgrep scan complete: {len(issue_data)} findings")
        return output
