from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from typing import Optional, List
from sqlalchemy.orm import Session

from src.db.session import get_db
from src.services.scanning.orchestrator import ScanOrchestrator
from src.services.scanning.upload_handler import CodeUploadHandler
from src.db.postgres.models import ScanResults

router = APIRouter()

@router.post("/scan/git")
async def scan_git_repository(
    repository_url: str,
    branch: str = "main",
    framework_id: int = 1,  # Default to first framework
    scan_types: List[str] = ["sast"],  # Default to SAST only
    db: Session = Depends(get_db)
):
    """
    Initiate a security scan for a Git repository
    """
    try:
        orchestrator = ScanOrchestrator(db)
        scan_id = await orchestrator.initiate_scan(
            repository_url=repository_url,
            branch=branch,
            framework_id=framework_id,
            scan_types=scan_types
        )
        
        return {
            "scan_id": scan_id,
            "status": "initiated",
            "repository_url": repository_url,
            "branch": branch
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initiate scan: {str(e)}"
        )

@router.post("/scan/upload")
async def scan_uploaded_code(
    file: UploadFile = File(...),
    framework_id: int = Form(1),  # Default to first framework
    scan_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Scan uploaded code files (ZIP or TAR archives)
    """
    handler = CodeUploadHandler()
    try:
        return await handler.handle_upload(
            file=file,
            framework_id=framework_id,
            scan_name=scan_name
        )
    finally:
        handler.cleanup()

@router.get("/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Get the status and results of a scan
    """
    try:
        orchestrator = ScanOrchestrator(db)
        return await orchestrator.get_scan_status(scan_id)
        
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Scan not found: {str(e)}"
        )

@router.get("/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Get detailed results of a completed scan
    """
    scan_result = db.query(ScanResults).filter(
        ScanResults.scan_id == scan_id
    ).first()
    
    if not scan_result:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )
    
    if scan_result.status != "complete":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not complete. Current status: {scan_result.status}"
        )
    
    return {
        "scan_id": scan_id,
        "findings": scan_result.findings,
        "compliance_score": scan_result.compliance_score,
        "scan_date": scan_result.scan_date,
        "repository_url": scan_result.repository_url,
        "branch": scan_result.branch
    }