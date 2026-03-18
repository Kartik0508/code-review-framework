from .sonarqube import SonarQubeScanner
from .semgrep_scanner import SemgrepScanner
from .bandit_scanner import BanditScanner
from .gitleaks_scanner import GitleaksScanner
from .dependency_check import DependencyCheckScanner

ScannerRegistry = {
    "sonarqube": SonarQubeScanner,
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "gitleaks": GitleaksScanner,
    "dependency-check": DependencyCheckScanner,
}
