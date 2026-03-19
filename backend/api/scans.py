import hashlib
import hmac
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from loguru import logger
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security import get_current_user, require_role
from backend.db.database import get_db
from backend.db.models import Issue, Project, ScanResult, User
from backend.models.schemas import IssueResponse, IssueUpdate, ScanResultResponse, ScanTrigger

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("/", response_model=list[ScanResultResponse])
def list_scans(
    project_id: UUID | None = None,
    scanner: str | None = None,
    scan_status: str | None = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = db.query(ScanResult)
    if project_id:
        q = q.filter(ScanResult.project_id == project_id)
    if scanner:
        q = q.filter(ScanResult.scanner == scanner)
    if scan_status:
        q = q.filter(ScanResult.status == scan_status)
    return q.order_by(ScanResult.started_at.desc()).offset(skip).limit(limit).all()


@router.get("/{scan_id}", response_model=ScanResultResponse)
def get_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/issues", response_model=list[IssueResponse])
def get_scan_issues(
    scan_id: UUID,
    severity: str | None = None,
    issue_status: str | None = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    q = db.query(Issue).filter(Issue.scan_id == scan_id)
    if severity:
        q = q.filter(Issue.severity == severity.upper())
    if issue_status:
        q = q.filter(Issue.status == issue_status)
    return q.order_by(Issue.severity).offset(skip).limit(limit).all()


@router.put("/{scan_id}/issues/{issue_id}", response_model=IssueResponse)
def update_issue(
    scan_id: UUID,
    issue_id: UUID,
    payload: IssueUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin", "reviewer")),
):
    allowed = {"open", "resolved", "false_positive"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {allowed}")

    issue = db.query(Issue).filter(Issue.id == issue_id, Issue.scan_id == scan_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")

    issue.status = payload.status
    db.commit()
    db.refresh(issue)
    return issue


@router.post("/trigger", response_model=ScanResultResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(
    project_id: UUID,
    payload: ScanTrigger,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "reviewer")),
):
    project = db.query(Project).filter(Project.id == project_id, Project.is_active == True).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    scan = ScanResult(
        project_id=project.id,
        scanner=payload.scanner,
        status="pending",
        commit_sha=payload.commit_sha,
        branch=payload.branch,
        triggered_by=current_user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from backend.scanners.scanner_service import ScannerService
    service = ScannerService()
    background_tasks.add_task(
        service.run_scan,
        scan_id=str(scan.id),
        scanner_name=payload.scanner,
        repo_path=project.repo_url,
    )

    return scan


@router.post("/webhook/github", status_code=status.HTTP_200_OK)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()

    # Validate HMAC signature
    if x_hub_signature_256:
        expected = "sha256=" + hmac.new(
            settings.GITHUB_WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    ref = payload.get("ref", "")
    commit_sha = payload.get("after", "")
    repo_url = payload.get("repository", {}).get("clone_url", "")
    branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref

    # Only scan pushes to main/master
    if branch not in ("main", "master"):
        return {"message": f"Branch '{branch}' not configured for auto-scan"}

    # Find matching project by repo URL
    project = db.query(Project).filter(
        Project.repo_url == repo_url,
        Project.is_active == True,
    ).first()

    if not project:
        logger.info(f"No project found for repo URL: {repo_url}")
        return {"message": "No matching project configured"}

    # Trigger all scanners
    from backend.scanners.scanner_service import ScannerService
    service = ScannerService()

    for scanner_name in ["semgrep", "bandit", "gitleaks"]:
        scan = ScanResult(
            project_id=project.id,
            scanner=scanner_name,
            status="pending",
            commit_sha=commit_sha,
            branch=branch,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        background_tasks.add_task(
            service.run_scan,
            scan_id=str(scan.id),
            scanner_name=scanner_name,
            repo_path=repo_url,
        )

    return {"message": f"Triggered scans for project '{project.name}'", "branch": branch, "commit": commit_sha}
