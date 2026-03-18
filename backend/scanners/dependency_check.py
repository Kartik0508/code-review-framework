import asyncio
import json
import os
import re
import shutil
import tempfile
from typing import Optional

from loguru import logger

from backend.scanners.base import BaseScanner, IssueData, ScanOutput

REMEDIATION = (
    "Upgrade the dependency to the patched version listed in the CVE advisory. "
    "Enable automated dependency scanning in your CI/CD pipeline to detect vulnerabilities early."
)

# Known vulnerable packages: {package: [(version_constraint, CVE, severity, description)]}
KNOWN_VULNERABLE: dict[str, list[tuple]] = {
    "django": [
        ("< 3.2.20", "CVE-2023-36053", "HIGH", "Potential ReDoS in EmailValidator and URLValidator"),
        ("< 4.2.3",  "CVE-2023-36053", "HIGH", "Potential ReDoS in EmailValidator and URLValidator"),
    ],
    "requests": [
        ("< 2.31.0", "CVE-2023-32681", "MEDIUM", "Unintended leak of Proxy-Authorization header"),
    ],
    "cryptography": [
        ("< 41.0.0", "CVE-2023-38325", "HIGH", "NULL pointer dereference in PKCS12 parsing"),
    ],
    "pillow": [
        ("< 10.0.0", "CVE-2023-44271", "HIGH", "Uncontrolled resource consumption in ImageFont"),
        ("< 9.3.0",  "CVE-2022-45199", "HIGH", "PIL.ImageFont.getsize DoS"),
    ],
    "flask": [
        ("< 2.3.2",  "CVE-2023-30861", "HIGH", "Cookie incorrectly sent to third-party sites"),
    ],
    "werkzeug": [
        ("< 3.0.1",  "CVE-2023-46136", "HIGH", "Client could trigger high memory usage and CPU usage"),
    ],
    "sqlalchemy": [
        ("< 1.4.49", "CVE-2023-30608", "MEDIUM", "Possible SQL injection via crafted string"),
    ],
    "paramiko": [
        ("< 3.4.0",  "CVE-2023-48795", "MEDIUM", "Prefix truncation attack on Binary Packet Protocol"),
    ],
    "urllib3": [
        ("< 1.26.17","CVE-2023-43804", "HIGH", "Cookie request header not stripped on redirect"),
        ("< 2.0.6",  "CVE-2023-45803", "MEDIUM", "Cookie request header not stripped on redirect"),
    ],
    "aiohttp": [
        ("< 3.9.0",  "CVE-2023-49081", "HIGH", "HTTP request smuggling via Content-Length/Transfer-Encoding"),
    ],
    "pycryptodome": [
        ("< 3.19.1", "CVE-2023-52323", "MEDIUM", "Side-channel leakage in OAEP decryption"),
    ],
    "jinja2": [
        ("< 3.1.3",  "CVE-2024-22195", "MEDIUM", "XSS via the xmlattr filter"),
    ],
}


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a tuple for comparison."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts)


def _version_matches(installed: str, constraint: str) -> bool:
    """Check if installed version satisfies constraint like '< 3.2.20'."""
    constraint = constraint.strip()
    if constraint.startswith("< "):
        limit = _parse_version(constraint[2:])
        return _parse_version(installed) < limit
    if constraint.startswith("<= "):
        limit = _parse_version(constraint[3:])
        return _parse_version(installed) <= limit
    if constraint.startswith(">= "):
        limit = _parse_version(constraint[3:])
        return _parse_version(installed) >= limit
    return False


def _parse_requirements_txt(path: str) -> dict[str, str]:
    """Parse requirements.txt → {package_name: version}."""
    packages: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle ==, >=, ~=
            m = re.match(r"^([A-Za-z0-9_\-]+)[=~><!]+([0-9][0-9.]*)", line)
            if m:
                pkg = m.group(1).lower().replace("_", "-")
                ver = m.group(2)
                packages[pkg] = ver
    return packages


def _parse_package_json(path: str) -> dict[str, str]:
    """Parse package.json → {package: version}."""
    with open(path) as f:
        data = json.load(f)
    packages: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for pkg, ver in data.get(section, {}).items():
            clean = re.sub(r"[^0-9.]", "", ver)
            if clean:
                packages[pkg.lower()] = clean
    return packages


class DependencyCheckScanner(BaseScanner):
    name = "dependency-check"

    async def scan(self, repo_path: str, project_id: str, scan_id: str, **kwargs) -> ScanOutput:
        scan_target = repo_path if os.path.isdir(repo_path) else "."

        # Try official OWASP Dependency-Check binary first
        dc_bin = shutil.which("dependency-check") or shutil.which("dependency-check.sh")
        if dc_bin:
            return await self._run_odc(dc_bin, scan_target, scan_id)

        # Fallback: manual requirements.txt / package.json check
        return await self._fallback_scan(scan_target)

    async def _run_odc(self, binary: str, scan_target: str, scan_id: str) -> ScanOutput:
        report_dir = os.path.join(tempfile.gettempdir(), f"odc_{scan_id}")
        os.makedirs(report_dir, exist_ok=True)

        cmd = [
            binary,
            "--scan", scan_target,
            "--format", "JSON",
            "--out", report_dir,
            "--disableAssembly",
        ]

        logger.info(f"Running OWASP Dependency-Check: {' '.join(cmd)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            return ScanOutput(scanner=self.name, status="failed", error="Dependency-Check timed out")
        except FileNotFoundError as exc:
            return ScanOutput(scanner=self.name, status="failed", error=str(exc))

        # Find the JSON report
        report_path = os.path.join(report_dir, "dependency-check-report.json")
        if not os.path.exists(report_path):
            return ScanOutput(scanner=self.name, status="failed", error="Dependency-Check report not generated")

        with open(report_path) as f:
            data = json.load(f)

        issue_data: list[IssueData] = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                cve_id = vuln.get("name", "UNKNOWN")
                cvss_score = vuln.get("cvssv3", {}).get("baseScore") or vuln.get("cvssv2", {}).get("score", 0)
                severity = "CRITICAL" if cvss_score >= 9 else "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW"

                issue_data.append(IssueData(
                    rule_id=cve_id,
                    severity=severity,
                    title=f"Vulnerable dependency: {dep.get('fileName', 'unknown')} ({cve_id})",
                    description=vuln.get("description", ""),
                    file_path=dep.get("filePath"),
                    cwe_id="CWE-1035",
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    remediation=REMEDIATION,
                ))

        output = ScanOutput(scanner=self.name, status="completed", issues=issue_data)
        output.compute_summary()
        return output

    async def _fallback_scan(self, scan_target: str) -> ScanOutput:
        """Simplified fallback that checks requirements.txt and package.json."""
        logger.info("OWASP Dependency-Check not found, using built-in CVE database fallback")
        issue_data: list[IssueData] = []

        packages: dict[str, str] = {}

        req_path = os.path.join(scan_target, "requirements.txt")
        if os.path.exists(req_path):
            try:
                packages.update(_parse_requirements_txt(req_path))
            except Exception as exc:
                logger.warning(f"Failed to parse requirements.txt: {exc}")

        pkg_path = os.path.join(scan_target, "package.json")
        if os.path.exists(pkg_path):
            try:
                packages.update(_parse_package_json(pkg_path))
            except Exception as exc:
                logger.warning(f"Failed to parse package.json: {exc}")

        for pkg_name, installed_version in packages.items():
            if pkg_name in KNOWN_VULNERABLE:
                for constraint, cve, severity, description in KNOWN_VULNERABLE[pkg_name]:
                    try:
                        if _version_matches(installed_version, constraint):
                            issue_data.append(IssueData(
                                rule_id=cve,
                                severity=severity,
                                title=f"Vulnerable dependency: {pkg_name}=={installed_version} ({cve})",
                                description=f"{description}. Installed: {installed_version}, constraint: {constraint}",
                                cwe_id="CWE-1035",
                                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                                remediation=REMEDIATION,
                            ))
                    except Exception:
                        pass  # Skip unparseable version strings

        output = ScanOutput(scanner=self.name, status="completed", issues=issue_data)
        output.compute_summary()
        logger.info(f"Dependency fallback scan complete: {len(issue_data)} findings")
        return output
