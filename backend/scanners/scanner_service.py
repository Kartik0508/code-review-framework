import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timezone

from loguru import logger
from sqlalchemy.orm import Session

from backend.db.database import SessionLocal
from backend.db.models import Issue, ScanResult
from backend.scanners import ScannerRegistry
from backend.scanners.base import IssueData, ScanOutput


class ScannerService:

    async def run_scan(
        self,
        scan_id: str,
        scanner_name: str,
        repo_path: str,
        **kwargs,
    ) -> None:
        """Run a scan and persist results to the database."""
        db: Session = SessionLocal()
        cloned_path: str | None = None

        try:
            scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
            if not scan:
                logger.error(f"Scan record {scan_id} not found in database")
                return

            # Mark as running
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            db.commit()

            # Clone repo if it's a remote URL
            if repo_path.startswith(("http://", "https://", "git@")):
                try:
                    cloned_path = await self.get_or_clone_repo(repo_path, scan_id)
                    scan_target = cloned_path
                except Exception as exc:
                    logger.warning(f"Repo clone failed, scanning current dir: {exc}")
                    scan_target = "."
            else:
                scan_target = repo_path if os.path.isdir(repo_path) else "."

            # Get scanner class
            scanner_cls = ScannerRegistry.get(scanner_name)
            if not scanner_cls:
                scan.status = "failed"
                scan.finished_at = datetime.now(timezone.utc)
                scan.summary = {"error": f"Unknown scanner: {scanner_name}"}
                db.commit()
                return

            scanner = scanner_cls()
            project_id = str(scan.project_id)

            logger.info(f"Starting {scanner_name} scan {scan_id} on {scan_target}")
            output: ScanOutput = await scanner.scan(
                repo_path=scan_target,
                project_id=project_id,
                scan_id=scan_id,
                **kwargs,
            )

            # Persist issues
            for issue_data in output.issues:
                # Strip the temp clone prefix to store relative file paths
                file_path = issue_data.file_path
                if file_path and scan_target and file_path.startswith(scan_target):
                    file_path = file_path[len(scan_target):].lstrip("/")

                issue = Issue(
                    scan_id=scan_id,
                    rule_id=issue_data.rule_id,
                    severity=issue_data.severity,
                    title=issue_data.title,
                    description=issue_data.description,
                    file_path=file_path,
                    line_start=issue_data.line_start,
                    line_end=issue_data.line_end,
                    cwe_id=issue_data.cwe_id,
                    owasp_category=issue_data.owasp_category,
                    remediation=issue_data.remediation,
                )
                db.add(issue)

            # Update scan record
            scan.status = output.status
            scan.finished_at = datetime.now(timezone.utc)
            scan.summary = output.summary
            scan.raw_results = {"issue_count": len(output.issues), "scanner": scanner_name}
            db.commit()

            logger.info(
                f"Scan {scan_id} ({scanner_name}) finished: {output.status}, "
                f"{len(output.issues)} issues"
            )

        except Exception as exc:
            logger.exception(f"Unhandled error in scan {scan_id}: {exc}")
            try:
                scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
                if scan:
                    scan.status = "failed"
                    scan.finished_at = datetime.now(timezone.utc)
                    scan.summary = {"error": str(exc)}
                    db.commit()
            except Exception:
                pass
        finally:
            db.close()
            if cloned_path and os.path.isdir(cloned_path):
                try:
                    shutil.rmtree(cloned_path, ignore_errors=True)
                except Exception:
                    pass

    async def clone_repo(self, repo_url: str, target_dir: str) -> str:
        """Clone a git repository to target_dir. Returns the cloned path."""
        cmd = ["git", "clone", "--depth", "1", repo_url, target_dir]
        logger.info(f"Cloning repo: {repo_url} → {target_dir}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")
            raise RuntimeError(f"git clone failed (rc={proc.returncode}): {err}")

        return target_dir

    async def get_or_clone_repo(self, repo_url: str, scan_id: str) -> str:
        """Clone repo to a temporary directory and return the path."""
        base_dir = os.path.join(tempfile.gettempdir(), "scans")
        os.makedirs(base_dir, exist_ok=True)
        target = os.path.join(base_dir, scan_id)
        return await self.clone_repo(repo_url, target)
