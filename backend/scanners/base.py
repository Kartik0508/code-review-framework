from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# CWE → OWASP Top 10 (2021) mapping
OWASP_MAPPING: dict[str, str] = {
    "CWE-22":  "A01:2021 - Broken Access Control",
    "CWE-23":  "A01:2021 - Broken Access Control",
    "CWE-59":  "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-285": "A01:2021 - Broken Access Control",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-328": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-311": "A02:2021 - Cryptographic Failures",
    "CWE-312": "A02:2021 - Cryptographic Failures",
    "CWE-79":  "A03:2021 - Injection",
    "CWE-89":  "A03:2021 - Injection",
    "CWE-78":  "A03:2021 - Injection",
    "CWE-77":  "A03:2021 - Injection",
    "CWE-611": "A03:2021 - Injection",
    "CWE-94":  "A03:2021 - Injection",
    "CWE-1336":"A03:2021 - Injection",
    "CWE-73":  "A04:2021 - Insecure Design",
    "CWE-602": "A04:2021 - Insecure Design",
    "CWE-16":  "A05:2021 - Security Misconfiguration",
    "CWE-732": "A05:2021 - Security Misconfiguration",
    "CWE-1173":"A05:2021 - Security Misconfiguration",
    "CWE-1035":"A06:2021 - Vulnerable and Outdated Components",
    "CWE-937": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-259": "A07:2021 - Identification and Authentication Failures",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-321": "A07:2021 - Identification and Authentication Failures",
    "CWE-384": "A07:2021 - Identification and Authentication Failures",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-494": "A08:2021 - Software and Data Integrity Failures",
    "CWE-345": "A08:2021 - Software and Data Integrity Failures",
    "CWE-778": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-223": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-532": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-918": "A10:2021 - Server-Side Request Forgery",
    "CWE-676": "A05:2021 - Security Misconfiguration",
    "CWE-377": "A04:2021 - Insecure Design",
    "CWE-390": "A04:2021 - Insecure Design",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-295": "A02:2021 - Cryptographic Failures",
    "CWE-319": "A02:2021 - Cryptographic Failures",
    "CWE-605": "A05:2021 - Security Misconfiguration",
}

REMEDIATION_TEMPLATES: dict[str, str] = {
    "sql-injection": (
        "Use parameterized queries or prepared statements instead of string concatenation. "
        "Never build SQL queries from user-supplied input directly."
    ),
    "command-injection": (
        "Use subprocess with a list of arguments (not a shell string). "
        "Validate and sanitize all user input before passing to shell commands."
    ),
    "xss": (
        "Escape all user-supplied data before rendering in HTML. "
        "Use a templating engine with auto-escaping enabled."
    ),
    "hardcoded-credentials": (
        "Remove the credential from source code immediately. "
        "Use environment variables, a secrets manager (HashiCorp Vault, AWS Secrets Manager), "
        "or a configuration file excluded from version control."
    ),
    "path-traversal": (
        "Validate and normalize file paths. Use os.path.realpath() and verify the "
        "resolved path starts with the expected base directory."
    ),
    "insecure-deserialization": (
        "Avoid deserializing data from untrusted sources. "
        "Use safer alternatives like JSON. If pickle is required, validate a cryptographic "
        "signature before deserializing."
    ),
    "weak-crypto": (
        "Replace MD5/SHA1 with SHA-256 or stronger for hashing. "
        "For passwords, use bcrypt, scrypt, or Argon2."
    ),
    "ssrf": (
        "Validate and whitelist allowed URL schemes and hosts. "
        "Use a DNS/URL allowlist and block internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
    ),
    "secret-exposure": (
        "Rotate the exposed credential immediately. "
        "Remove it from git history using git-filter-repo or BFG Repo-Cleaner. "
        "Store secrets in environment variables or a dedicated secret store."
    ),
    "vulnerable-dependency": (
        "Upgrade the dependency to the patched version listed in the CVE advisory. "
        "Enable automated dependency scanning in CI/CD to catch future vulnerabilities."
    ),
}


@dataclass
class IssueData:
    rule_id: str
    severity: str
    title: str
    description: str = ""
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class ScanOutput:
    scanner: str
    status: str  # completed / failed
    issues: list[IssueData] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None

    def __post_init__(self):
        if not self.summary:
            self.summary = self._compute_summary()

    def _compute_summary(self) -> dict:
        counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in self.issues:
            counts["total"] += 1
            counts[issue.severity.lower()] = counts.get(issue.severity.lower(), 0) + 1
        return counts

    def compute_summary(self) -> dict:
        self.summary = self._compute_summary()
        return self.summary


class BaseScanner(ABC):
    name: str = "base"

    def severity_normalize(self, raw: str) -> str:
        mapping = {
            "blocker": "CRITICAL",
            "critical": "CRITICAL",
            "error": "HIGH",
            "major": "HIGH",
            "high": "HIGH",
            "warning": "MEDIUM",
            "minor": "MEDIUM",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "note": "INFO",
        }
        return mapping.get(raw.lower(), "MEDIUM")

    def get_owasp(self, cwe_id: Optional[str]) -> Optional[str]:
        if not cwe_id:
            return None
        normalized = cwe_id.upper().replace("CWE ", "CWE-")
        return OWASP_MAPPING.get(normalized)

    @abstractmethod
    async def scan(self, repo_path: str, project_id: str, scan_id: str, **kwargs) -> ScanOutput:
        ...
