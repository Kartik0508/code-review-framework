import asyncio
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

    async def _ensure_project_exists(self, client: httpx.AsyncClient, key: str, name: str) -> None:
        """Create the SonarQube project if it does not already exist."""
        check = await client.get(
            f"{settings.SONARQUBE_URL}/api/projects/search",
            params={"projects": key},
            auth=self._auth(),
        )
        if check.status_code == 200:
            components = check.json().get("components", [])
            if any(c["key"] == key for c in components):
                logger.info(f"SonarQube project '{key}' already exists — updating name to '{name}'")
                await client.post(
                    f"{settings.SONARQUBE_URL}/api/projects/update",
                    data={"project": key, "name": name},
                    auth=self._auth(),
                )
                return

        resp = await client.post(
            f"{settings.SONARQUBE_URL}/api/projects/create",
            data={"project": key, "name": name},
            auth=self._auth(),
        )
        if resp.status_code in (200, 201):
            logger.info(f"SonarQube project '{key}' created")
        else:
            logger.warning(f"Could not create SonarQube project '{key}': {resp.text[:300]}")

    async def _run_sonar_scanner(self, repo_path: str, key: str, name: str = "") -> bool:
        """Run sonar-scanner CLI against the repo. Returns True on success."""
        display_name = name or key
        cmd = [
            "sonar-scanner",
            f"-Dsonar.projectKey={key}",
            f"-Dsonar.projectName={display_name}",
            f"-Dsonar.sources=.",
            f"-Dsonar.host.url={settings.SONARQUBE_URL}",
            f"-Dsonar.token={settings.SONARQUBE_TOKEN}",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.sourceEncoding=UTF-8",
        ]
        logger.info(f"Running sonar-scanner on '{repo_path}' for project '{key}'")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            logger.error("sonar-scanner timed out after 5 minutes")
            return False
        except FileNotFoundError:
            logger.error("sonar-scanner binary not found in PATH")
            return False

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[-1000:]
            logger.error(f"sonar-scanner failed (rc={proc.returncode}): {err}")
            return False

        logger.info("sonar-scanner finished successfully")
        return True

    async def _wait_for_analysis(self, client: httpx.AsyncClient, key: str, timeout: int = 120) -> bool:
        """Poll SonarQube background task queue until analysis completes."""
        logger.info(f"Waiting for SonarQube analysis of '{key}' to complete ...")
        for _ in range(timeout // 5):
            await asyncio.sleep(5)
            resp = await client.get(
                f"{settings.SONARQUBE_URL}/api/ce/component",
                params={"component": key},
                auth=self._auth(),
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            current = data.get("current", {})
            status = current.get("status", "")
            if status == "SUCCESS":
                logger.info(f"SonarQube analysis for '{key}' completed")
                return True
            if status in ("FAILED", "CANCELED"):
                logger.error(f"SonarQube analysis for '{key}' ended with status: {status}")
                return False
        logger.warning(f"Timed out waiting for SonarQube analysis of '{key}'")
        return False

    async def scan(self, repo_path: str, project_id: str, scan_id: str,
                   sonarqube_project_key: Optional[str] = None, **kwargs) -> ScanOutput:
        key = sonarqube_project_key or project_id
        name = kwargs.get("project_name", key)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # 1. Auto-create project in SonarQube if needed
                await self._ensure_project_exists(client, key, name)

            # 2. Run sonar-scanner to analyse the code
            success = await self._run_sonar_scanner(repo_path, key, name)
            if not success:
                return ScanOutput(
                    scanner=self.name,
                    status="failed",
                    error=f"sonar-scanner analysis failed for project '{key}'",
                )

            async with httpx.AsyncClient(timeout=30) as client:
                # 3. Wait for SonarQube to process the results
                await self._wait_for_analysis(client, key)

                # 4. Fetch issues
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
                        error=f"SonarQube project '{key}' not found after analysis.",
                    )

                issues_resp.raise_for_status()
                data = issues_resp.json()
                raw_issues = data.get("issues", [])

                # 5. Fetch metrics
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
