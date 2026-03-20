import asyncio
import json
import os
import shutil
import tempfile
from typing import Optional

from loguru import logger

from backend.scanners.base import BaseScanner, IssueData, REMEDIATION_TEMPLATES, ScanOutput

# eslint-plugin-security rule → CWE mapping
ESLINT_CWE: dict[str, str] = {
    "security/detect-eval-with-expression":        "CWE-94",
    "security/detect-non-literal-fs-filename":     "CWE-22",
    "security/detect-non-literal-regexp":          "CWE-1333",
    "security/detect-non-literal-require":         "CWE-94",
    "security/detect-object-injection":            "CWE-89",
    "security/detect-possible-timing-attacks":     "CWE-208",
    "security/detect-pseudoRandomBytes":           "CWE-330",
    "security/detect-unsafe-regex":                "CWE-1333",
    "security/detect-buffer-noassert":             "CWE-20",
    "security/detect-child-process":              "CWE-78",
    "security/detect-disable-mustache-escape":    "CWE-79",
    "security/detect-new-buffer":                  "CWE-20",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-bidi-characters":            "CWE-116",
    "no-eval":                                     "CWE-94",
    "no-implied-eval":                             "CWE-94",
    "no-new-func":                                 "CWE-94",
}

# ESLint severity: 1 = warn, 2 = error
ESLINT_SEVERITY_MAP: dict[int, str] = {
    2: "HIGH",
    1: "MEDIUM",
}

# Minimal .eslintrc.json content enabling security plugin
_ESLINT_CONFIG = json.dumps({
    "plugins": ["security"],
    "extends": ["plugin:security/recommended"],
    "env": {"node": True, "es2021": True},
    "parserOptions": {"ecmaVersion": 2021},
    "rules": {
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error",
    },
})

# package.json for temp install
_PACKAGE_JSON = json.dumps({
    "name": "eslint-security-scan",
    "version": "1.0.0",
    "private": True,
})


class ESLintScanner(BaseScanner):
    name = "eslint"

    async def scan(self, repo_path: str, project_id: str, scan_id: str, **kwargs) -> ScanOutput:
        scan_target = repo_path if os.path.isdir(repo_path) else "."

        # Find npm — required to install eslint + plugin
        if not shutil.which("npm"):
            return ScanOutput(
                scanner=self.name,
                status="failed",
                error="npm not found. Install Node.js to enable ESLint scanning.",
            )

        # Create isolated temp dir so we don't pollute the scanned repo
        tmp_dir = tempfile.mkdtemp(prefix="eslint-scan-")
        try:
            return await self._run(scan_target, tmp_dir)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def _run(self, scan_target: str, tmp_dir: str) -> ScanOutput:
        # Write package.json and .eslintrc.json into the temp dir
        with open(os.path.join(tmp_dir, "package.json"), "w") as f:
            f.write(_PACKAGE_JSON)
        with open(os.path.join(tmp_dir, ".eslintrc.json"), "w") as f:
            f.write(_ESLINT_CONFIG)

        # Install eslint + eslint-plugin-security locally in tmp_dir
        logger.info("ESLint: installing eslint + eslint-plugin-security ...")
        install_cmd = [
            "npm", "install", "--save-dev", "--prefix", tmp_dir,
            "eslint@8", "eslint-plugin-security",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=tmp_dir,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            return ScanOutput(scanner=self.name, status="failed", error="npm install timed out")

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[:1000]
            return ScanOutput(scanner=self.name, status="failed", error=f"npm install failed: {err}")

        eslint_bin = os.path.join(tmp_dir, "node_modules", ".bin", "eslint")

        # Run ESLint against the scanned repo
        cmd = [
            eslint_bin,
            "--no-eslintrc",
            "-c", os.path.join(tmp_dir, ".eslintrc.json"),
            "--resolve-plugins-relative-to", tmp_dir,
            "--ext", ".js,.mjs,.cjs,.jsx,.ts,.tsx",
            "--format", "json",
            "--no-error-on-unmatched-pattern",
            scan_target,
        ]
        logger.info(f"Running ESLint on {scan_target}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            return ScanOutput(scanner=self.name, status="failed", error="ESLint timed out after 5 minutes")

        # ESLint exits 0 (no issues), 1 (lint issues found), 2 (config/runtime error)
        if proc.returncode == 2:
            err = stderr.decode(errors="replace")[:2000]
            return ScanOutput(scanner=self.name, status="failed", error=f"ESLint error: {err}")

        raw = stdout.decode(errors="replace").strip()
        if not raw:
            return ScanOutput(scanner=self.name, status="completed", issues=[])

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ScanOutput(scanner=self.name, status="failed", error=f"Failed to parse ESLint output: {exc}")

        issues: list[IssueData] = []
        for file_result in data:
            file_path = file_result.get("filePath", "")
            for msg in file_result.get("messages", []):
                rule_id = msg.get("ruleId") or "eslint/unknown"
                eslint_sev = msg.get("severity", 1)
                severity = ESLINT_SEVERITY_MAP.get(eslint_sev, "MEDIUM")

                cwe_id = ESLINT_CWE.get(rule_id)
                owasp_category = self.get_owasp(cwe_id)

                remediation = self._get_remediation(rule_id)

                issues.append(IssueData(
                    rule_id=rule_id,
                    severity=severity,
                    title=msg.get("message", rule_id),
                    description=f"ESLint rule: {rule_id}",
                    file_path=file_path,
                    line_start=msg.get("line"),
                    line_end=msg.get("endLine"),
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                    remediation=remediation,
                ))

        output = ScanOutput(scanner=self.name, status="completed", issues=issues)
        output.compute_summary()
        logger.info(f"ESLint scan complete: {len(issues)} findings")
        return output

    def _get_remediation(self, rule_id: str) -> Optional[str]:
        rule_lower = rule_id.lower()
        keyword_map = {
            "eval":        "xss",
            "regexp":      None,
            "fs-filename": "path-traversal",
            "child":       "command-injection",
            "mustache":    "xss",
            "csrf":        None,
            "timing":      None,
            "random":      "weak-crypto",
            "injection":   "sql-injection",
        }
        for keyword, template_key in keyword_map.items():
            if keyword in rule_lower and template_key:
                return REMEDIATION_TEMPLATES.get(template_key)

        if "eval" in rule_lower or "func" in rule_lower:
            return (
                "Avoid eval() and new Function(). Use safer alternatives such as "
                "JSON.parse() for data or dedicated parsers for dynamic logic."
            )
        return None
