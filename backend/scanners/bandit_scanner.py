import asyncio
import json
import os
from typing import Optional

from loguru import logger

from backend.scanners.base import BaseScanner, IssueData, OWASP_MAPPING, REMEDIATION_TEMPLATES, ScanOutput

# Bandit test ID → CWE mapping
BANDIT_CWE: dict[str, str] = {
    "B101": "CWE-676",
    "B102": "CWE-78",
    "B103": "CWE-732",
    "B104": "CWE-605",
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    "B108": "CWE-377",
    "B110": "CWE-390",
    "B112": "CWE-390",
    "B201": "CWE-78",
    "B202": "CWE-78",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-78",
    "B308": "CWE-352",
    "B310": "CWE-78",
    "B311": "CWE-330",
    "B312": "CWE-78",
    "B313": "CWE-611",
    "B314": "CWE-611",
    "B315": "CWE-611",
    "B316": "CWE-611",
    "B317": "CWE-611",
    "B318": "CWE-611",
    "B319": "CWE-611",
    "B320": "CWE-611",
    "B321": "CWE-319",
    "B322": "CWE-78",
    "B323": "CWE-295",
    "B324": "CWE-327",
    "B325": "CWE-327",
    "B401": "CWE-676",
    "B402": "CWE-319",
    "B403": "CWE-502",
    "B404": "CWE-78",
    "B405": "CWE-611",
    "B406": "CWE-611",
    "B407": "CWE-611",
    "B408": "CWE-611",
    "B409": "CWE-611",
    "B410": "CWE-611",
    "B411": "CWE-311",
    "B412": "CWE-319",
    "B413": "CWE-327",
    "B501": "CWE-326",
    "B502": "CWE-326",
    "B503": "CWE-326",
    "B504": "CWE-326",
    "B505": "CWE-326",
    "B506": "CWE-311",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    "B607": "CWE-78",
    "B608": "CWE-89",
    "B609": "CWE-78",
    "B610": "CWE-89",
    "B611": "CWE-89",
    "B612": "CWE-78",
    "B701": "CWE-79",
    "B702": "CWE-79",
    "B703": "CWE-79",
}

BANDIT_SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


class BanditScanner(BaseScanner):
    name = "bandit"

    async def scan(self, repo_path: str, project_id: str, scan_id: str, **kwargs) -> ScanOutput:
        scan_target = repo_path if os.path.isdir(repo_path) else "."

        cmd = ["bandit", "-r", scan_target, "-f", "json", "-ll"]
        logger.info(f"Running bandit: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            return ScanOutput(scanner=self.name, status="failed", error="Bandit timed out after 5 minutes")
        except FileNotFoundError:
            return ScanOutput(scanner=self.name, status="failed", error="bandit binary not found")

        # Bandit exits with 1 when issues found, which is expected
        if proc.returncode not in (0, 1):
            err = stderr.decode(errors="replace")[:2000]
            return ScanOutput(scanner=self.name, status="failed", error=f"Bandit error (rc={proc.returncode}): {err}")

        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            return ScanOutput(scanner=self.name, status="failed", error=f"Failed to parse bandit output: {exc}")

        issue_data: list[IssueData] = []
        for result in data.get("results", []):
            confidence = result.get("issue_confidence", "LOW")
            if confidence == "LOW":
                continue  # Filter low-confidence findings

            test_id = result.get("test_id", "B000")
            severity = BANDIT_SEVERITY_MAP.get(result.get("issue_severity", "MEDIUM"), "MEDIUM")
            cwe_id = BANDIT_CWE.get(test_id)
            owasp_category = self.get_owasp(cwe_id)

            # Select remediation template
            remediation = None
            test_name = result.get("test_name", "").lower()
            for key, template in REMEDIATION_TEMPLATES.items():
                if key.replace("-", "_") in test_name or key in test_name:
                    remediation = template
                    break
            if not remediation and result.get("more_info"):
                remediation = f"See: {result['more_info']}"

            line_range = result.get("line_range", [])
            line_end = line_range[-1] if line_range else result.get("line_number")

            issue_data.append(IssueData(
                rule_id=test_id,
                severity=severity,
                title=result.get("test_name", test_id),
                description=result.get("issue_text", ""),
                file_path=result.get("filename"),
                line_start=result.get("line_number"),
                line_end=line_end,
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                remediation=remediation,
            ))

        output = ScanOutput(scanner=self.name, status="completed", issues=issue_data)
        output.compute_summary()
        logger.info(f"Bandit scan complete: {len(issue_data)} findings")
        return output
