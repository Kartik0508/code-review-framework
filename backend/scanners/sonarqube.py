from typing import Optional

import httpx
from loguru import logger

from backend.core.config import settings
from backend.scanners.base import BaseScanner, IssueData, OWASP_MAPPING, ScanOutput

SONAR_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "MAJOR": "HIGH",
    "MINOR": "MEDIUM",
    "INFO": "LOW",
}

# SonarQube rule prefix → CWE approximation
SONAR_RULE_CWE: dict[str, str] = {
    "squid:S2068": "CWE-259",
    "squid:S2076": "CWE-78",
    "squid:S2083": "CWE-22",
    "squid:S2091": "CWE-643",
    "squid:S2631": "CWE-625",
    "squid:S3649": "CWE-89",
    "javasecurity:S3649": "CWE-89",
    "php:S2083": "CWE-22",
    "python:S2076": "CWE-78",
    "javascript:S2083": "CWE-22",
    "javascript:S5247": "CWE-79",
    "javascript:S5122": "CWE-346",
    "python:S5659": "CWE-347",
}


class SonarQubeScanner(BaseScanner):
    name = "sonarqube"

    def _auth(self) -> Optional[tuple]:
        if settings.SONARQUBE_TOKEN:
            return (settings.SONARQUBE_TOKEN, "")
        return None

    async def scan(self, repo_path: str, project_id: str, scan_id: str,
                   sonarqube_project_key: Optional[str] = None, **kwargs) -> ScanOutput:
        key = sonarqube_project_key or project_id

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Fetch issues
                issues_resp = await client.get(
                    f"{settings.SONARQUBE_URL}/api/issues/search",
                    params={
                        "componentKeys": key,
                        "resolved": "false",
                        "ps": 500,
                        "types": "VULNERABILITY,BUG,CODE_SMELL",
                    },
                    auth=self._auth(),
                )

                if issues_resp.status_code == 404:
                    return ScanOutput(
                        scanner=self.name,
                        status="failed",
                        error=f"SonarQube project '{key}' not found. Trigger a SonarQube analysis first.",
                    )

                issues_resp.raise_for_status()
                data = issues_resp.json()
                raw_issues = data.get("issues", [])

                # Fetch metrics
                metrics_resp = await client.get(
                    f"{settings.SONARQUBE_URL}/api/measures/component",
                    params={
                        "component": key,
                        "metricKeys": "bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density",
                    },
                    auth=self._auth(),
                )
                metrics = {}
                if metrics_resp.status_code == 200:
                    for m in metrics_resp.json().get("component", {}).get("measures", []):
                        metrics[m["metric"]] = m.get("value")

        except httpx.ConnectError as exc:
            return ScanOutput(scanner=self.name, status="failed", error=f"Cannot connect to SonarQube: {exc}")
        except httpx.HTTPStatusError as exc:
            return ScanOutput(scanner=self.name, status="failed", error=f"SonarQube API error: {exc}")

        issue_data: list[IssueData] = []
        for item in raw_issues:
            rule_id = item.get("rule", "unknown")
            severity = SONAR_SEVERITY_MAP.get(item.get("severity", "MAJOR"), "MEDIUM")
            component = item.get("component", "")
            text_range = item.get("textRange", {})

            cwe_id = SONAR_RULE_CWE.get(rule_id)
            owasp = self.get_owasp(cwe_id) if cwe_id else None

            issue_data.append(IssueData(
                rule_id=rule_id,
                severity=severity,
                title=item.get("message", rule_id),
                description=item.get("message", ""),
                file_path=component.split(":")[-1] if ":" in component else component,
                line_start=text_range.get("startLine"),
                line_end=text_range.get("endLine"),
                cwe_id=cwe_id,
                owasp_category=owasp,
            ))

        output = ScanOutput(scanner=self.name, status="completed", issues=issue_data)
        output.compute_summary()
        output.summary["metrics"] = metrics
        output.summary["raw_issue_count"] = data.get("total", len(raw_issues))

        logger.info(f"SonarQube scan complete for '{key}': {len(issue_data)} issues")
        return output
