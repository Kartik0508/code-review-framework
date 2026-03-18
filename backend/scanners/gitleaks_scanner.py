import asyncio
import json
import os
import shutil
import tempfile
from typing import Optional

from loguru import logger

from backend.scanners.base import BaseScanner, IssueData, ScanOutput

GITLEAKS_REMEDIATION = (
    "Remove the secret from source code immediately. "
    "Rotate the exposed credential with your service provider. "
    "Use environment variables, a secrets manager (HashiCorp Vault, AWS Secrets Manager, "
    "GitHub Secrets), or a .env file excluded via .gitignore. "
    "Clean git history with git-filter-repo or BFG Repo-Cleaner to remove historical exposure."
)


class GitleaksScanner(BaseScanner):
    name = "gitleaks"

    async def scan(self, repo_path: str, project_id: str, scan_id: str, **kwargs) -> ScanOutput:
        if not shutil.which("gitleaks"):
            return ScanOutput(
                scanner=self.name,
                status="failed",
                error="gitleaks binary not found. Install from https://github.com/gitleaks/gitleaks/releases",
            )

        scan_target = repo_path if os.path.isdir(repo_path) else "."
        is_git_repo = os.path.isdir(os.path.join(scan_target, ".git"))

        report_file = os.path.join(tempfile.gettempdir(), f"gitleaks_{scan_id}.json")

        if is_git_repo:
            cmd = [
                "gitleaks", "detect",
                "--source", scan_target,
                "--report-format", "json",
                "--report-path", report_file,
                "--exit-code", "0",
            ]
        else:
            cmd = [
                "gitleaks", "detect",
                "--source", scan_target,
                "--no-git",
                "--report-format", "json",
                "--report-path", report_file,
                "--exit-code", "0",
            ]

        logger.info(f"Running gitleaks: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            return ScanOutput(scanner=self.name, status="failed", error="Gitleaks timed out after 5 minutes")

        findings = []
        if os.path.exists(report_file):
            try:
                with open(report_file) as f:
                    content = f.read().strip()
                    if content:
                        findings = json.loads(content)
                    if isinstance(findings, dict):
                        findings = [findings]
            except (json.JSONDecodeError, IOError) as exc:
                logger.warning(f"Failed to read gitleaks report: {exc}")
            finally:
                try:
                    os.unlink(report_file)
                except OSError:
                    pass

        issue_data: list[IssueData] = []
        for finding in findings:
            rule_id = finding.get("RuleID", finding.get("ruleId", "gitleaks-secret"))
            description = finding.get("Description", finding.get("description", "Secret detected"))
            file_path = finding.get("File", finding.get("file"))
            line_start = finding.get("StartLine", finding.get("startLine"))
            line_end = finding.get("EndLine", finding.get("endLine"))

            # Mask the matched secret in the description
            match = finding.get("Match", finding.get("match", ""))
            if match:
                description = f"{description} — Match: {match[:6]}***"

            issue_data.append(IssueData(
                rule_id=rule_id,
                severity="CRITICAL",
                title=f"Secret Detected: {description[:80]}",
                description=description,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation=GITLEAKS_REMEDIATION,
            ))

        output = ScanOutput(scanner=self.name, status="completed", issues=issue_data)
        output.compute_summary()
        logger.info(f"Gitleaks scan complete: {len(issue_data)} secrets found")
        return output
