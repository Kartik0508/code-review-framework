import csv
import io
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.core.security import get_current_user
from backend.db.database import get_db
from backend.db.models import Issue, ScanResult, User
from backend.models.schemas import ComplianceItem, ScanSummary, TrendPoint

router = APIRouter(prefix="/reports", tags=["Reports"])

OWASP_RISK = {
    "A01:2021": "HIGH",
    "A02:2021": "HIGH",
    "A03:2021": "CRITICAL",
    "A04:2021": "MEDIUM",
    "A05:2021": "HIGH",
    "A06:2021": "HIGH",
    "A07:2021": "CRITICAL",
    "A08:2021": "HIGH",
    "A09:2021": "MEDIUM",
    "A10:2021": "HIGH",
}


@router.get("/summary", response_model=ScanSummary)
def get_summary(
    project_id: UUID | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    scan_q = db.query(ScanResult)
    issue_q = db.query(Issue).join(ScanResult, Issue.scan_id == ScanResult.id)

    if project_id:
        scan_q = scan_q.filter(ScanResult.project_id == project_id)
        issue_q = issue_q.filter(ScanResult.project_id == project_id)

    total_scans = scan_q.count()
    open_issues = issue_q.filter(Issue.status == "open").count()

    def count_by_severity(sev: str) -> int:
        return issue_q.filter(Issue.status == "open", Issue.severity == sev).count()

    scanners_used = [
        r[0] for r in scan_q.with_entities(ScanResult.scanner).distinct().all()
    ]

    return ScanSummary(
        total_scans=total_scans,
        open_issues=open_issues,
        critical_count=count_by_severity("CRITICAL"),
        high_count=count_by_severity("HIGH"),
        medium_count=count_by_severity("MEDIUM"),
        low_count=count_by_severity("LOW"),
        scanners_used=scanners_used,
    )


@router.get("/trends", response_model=list[TrendPoint])
def get_trends(
    project_id: UUID | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    result = []

    for week_offset in range(11, -1, -1):
        week_start = now - timedelta(weeks=week_offset + 1)
        week_end = now - timedelta(weeks=week_offset)
        week_label = week_start.strftime("%Y-W%W")

        issue_q = (
            db.query(Issue)
            .join(ScanResult, Issue.scan_id == ScanResult.id)
            .filter(Issue.created_at >= week_start, Issue.created_at < week_end)
        )
        if project_id:
            issue_q = issue_q.filter(ScanResult.project_id == project_id)

        def week_count(sev: str) -> int:
            return issue_q.filter(Issue.severity == sev).count()

        result.append(TrendPoint(
            week=week_label,
            critical=week_count("CRITICAL"),
            high=week_count("HIGH"),
            medium=week_count("MEDIUM"),
            low=week_count("LOW"),
        ))

    return result


@router.get("/compliance", response_model=list[ComplianceItem])
def get_compliance(
    project_id: UUID | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    categories = [
        ("A01:2021 - Broken Access Control", "A01:2021"),
        ("A02:2021 - Cryptographic Failures", "A02:2021"),
        ("A03:2021 - Injection", "A03:2021"),
        ("A04:2021 - Insecure Design", "A04:2021"),
        ("A05:2021 - Security Misconfiguration", "A05:2021"),
        ("A06:2021 - Vulnerable Components", "A06:2021"),
        ("A07:2021 - Auth & Session Failures", "A07:2021"),
        ("A08:2021 - Software Integrity Failures", "A08:2021"),
        ("A09:2021 - Logging & Monitoring Failures", "A09:2021"),
        ("A10:2021 - Server-Side Request Forgery", "A10:2021"),
    ]

    result = []
    for label, code in categories:
        q = db.query(Issue).join(ScanResult).filter(
            Issue.status == "open",
            Issue.owasp_category.ilike(f"%{code}%"),
        )
        if project_id:
            q = q.filter(ScanResult.project_id == project_id)

        result.append(ComplianceItem(
            category=label,
            count=q.count(),
            risk_level=OWASP_RISK.get(code, "MEDIUM"),
        ))

    return result


@router.get("/export/csv")
def export_csv(
    project_id: UUID | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = db.query(Issue).join(ScanResult).filter(Issue.status == "open")
    if project_id:
        q = q.filter(ScanResult.project_id == project_id)

    issues = q.order_by(Issue.severity, Issue.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Scan ID", "Rule", "Severity", "Title",
        "File", "Line Start", "CWE", "OWASP Category",
        "Status", "Created At",
    ])
    for issue in issues:
        writer.writerow([
            str(issue.id), str(issue.scan_id), issue.rule_id, issue.severity,
            issue.title, issue.file_path or "", issue.line_start or "",
            issue.cwe_id or "", issue.owasp_category or "",
            issue.status, issue.created_at.isoformat(),
        ])

    output.seek(0)
    filename = f"issues_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
