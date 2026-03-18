import asyncio
import uuid
from uuid import UUID

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from loguru import logger
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security import get_current_user, require_role
from backend.db.database import get_db
from backend.db.models import Project, ScanResult, User
from backend.models.schemas import ProjectCreate, ProjectResponse, ProjectUpdate, ScanResultResponse, ScanTrigger

router = APIRouter(prefix="/projects", tags=["Projects"])


async def _create_sonarqube_project(key: str, name: str) -> bool:
    auth = (settings.SONARQUBE_TOKEN, "") if settings.SONARQUBE_TOKEN else None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{settings.SONARQUBE_URL}/api/projects/create",
                params={"project": key, "name": name},
                auth=auth,
            )
            return resp.status_code in (200, 400)  # 400 = already exists
    except Exception as exc:
        logger.warning(f"SonarQube project creation failed: {exc}")
        return False


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "reviewer")),
):
    if db.query(Project).filter(Project.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Project name already exists")

    project = Project(
        name=payload.name,
        description=payload.description,
        repo_url=payload.repo_url,
        sonarqube_project_key=payload.sonarqube_project_key,
        created_by=current_user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    if payload.sonarqube_project_key:
        await _create_sonarqube_project(payload.sonarqube_project_key, payload.name)

    return project


@router.get("/", response_model=list[ProjectResponse])
def list_projects(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return db.query(Project).filter(Project.is_active == True).offset(skip).limit(limit).all()


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: UUID,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == project_id, Project.is_active == True).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: UUID,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin", "reviewer")),
):
    project = db.query(Project).filter(Project.id == project_id, Project.is_active == True).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, field, value)

    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_200_OK)
def delete_project(
    project_id: UUID,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.is_active = False
    db.commit()
    return {"message": f"Project '{project.name}' deactivated"}


@router.post("/{project_id}/scan", response_model=ScanResultResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    project_id: UUID,
    payload: ScanTrigger,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == project_id, Project.is_active == True).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    valid_scanners = {"sonarqube", "semgrep", "bandit", "gitleaks", "dependency-check"}
    if payload.scanner not in valid_scanners:
        raise HTTPException(status_code=400, detail=f"Invalid scanner. Choose from: {valid_scanners}")

    scan = ScanResult(
        project_id=project_id,
        scanner=payload.scanner,
        status="pending",
        triggered_by=current_user.id,
        commit_sha=payload.commit_sha,
        branch=payload.branch,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run scan in background
    from backend.scanners.scanner_service import ScannerService
    service = ScannerService()
    repo_path = project.repo_url or "/tmp/no-repo"
    background_tasks.add_task(
        service.run_scan,
        scan_id=str(scan.id),
        scanner_name=payload.scanner,
        repo_path=repo_path,
        sonarqube_project_key=project.sonarqube_project_key,
    )

    return scan
