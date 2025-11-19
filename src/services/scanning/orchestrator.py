from typing import Dict, List, Optional
from datetime import datetime
import uuid
from sqlalchemy.orm import Session
from sqlalchemy.future import select

from src.db.postgres.models import ScanResult  # Changed from ScanResults to ScanResult
from src.workers.sast_worker import run_sast_scan
from src.workers.dast_worker import run_dast_scan
from src.workers.sca_worker import run_sca_scan
from src.services.scanning.scheduler import ScannerScheduler  # Changed from ScanScheduler
from src.core.logging import get_logger
from src.workers.celery_app import celery_app  # Added for Celery tasks

logger = get_logger(__name__)

class ScanOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        # Removed scheduler initialization as it's not implemented yet
    
    def initiate_scan(
        self,
        repository_url: str,
        branch: str,
        framework_id: int,
        scan_types: List[str] = ["sast", "dast", "sca"],
        priority: int = 5
    ) -> str:
        """
        Initiates a new security scan for the given repository.
        
        Args:
            repository_url: URL of the git repository to scan
            branch: Branch name to scan
            framework_id: ID of the compliance framework to use
            scan_types: List of scan types to perform
            priority: Priority of the scan (1-10, higher is more urgent)
            
        Returns:
            scan_id: Unique identifier for the scan
        """
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan_result = ScanResult(
            scan_id=scan_id,
            framework_id=framework_id,
            repository_url=repository_url,
            branch=branch,
            scan_date=datetime.utcnow(),
            status="pending",
            findings={},
            compliance_score=0.0,
            raw_output={}
        )
        
        self.db.add(scan_result)
        self.db.commit()
        
        try:
            # Queue different scan types
            scan_tasks = []
            
            if "sast" in scan_types:
                task = celery_app.send_task(
                    'src.workers.sast_worker.run_sast_scan',
                    args=[scan_id, repository_url, branch],
                    priority=priority,
                    queue="sast"
                )
                scan_tasks.append(task)
            
            if "dast" in scan_types:
                task = celery_app.send_task(
                    'src.workers.dast_worker.run_dast_scan',
                    args=[scan_id, repository_url],
                    priority=priority,
                    queue="dast"
                )
                scan_tasks.append(task)
            
            if "sca" in scan_types:
                task = celery_app.send_task(
                    'src.workers.sca_worker.run_sca_scan',
                    args=[scan_id, repository_url, branch],
                    priority=priority,
                    queue="sca"
                )
                scan_tasks.append(task)
            
            # Update scan status
            scan_result.status = "in_progress"
            self.db.commit()
            
            logger.info(f"Initiated scan {scan_id} for {repository_url}:{branch}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to initiate scan: {str(e)}")
            scan_result.status = "failed"
            self.db.commit()
            raise
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """
        Gets the current status of a scan.
        
        Args:
            scan_id: The ID of the scan to check
            
        Returns:
            Dict containing scan status and results if complete
        """
        scan_result = self.db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if not scan_result:
            raise ValueError(f"Scan {scan_id} not found")
        
        return {
            "scan_id": scan_id,
            "status": scan_result.status,
            "findings": scan_result.findings,
            "compliance_score": scan_result.compliance_score,
            "scan_date": scan_result.scan_date,
            "repository_url": scan_result.repository_url,
            "branch": scan_result.branch
        }
    
    def aggregate_results(self, scan_id: str) -> None:
        """
        Aggregates results from different scan types and updates the final score.
        
        Args:
            scan_id: The ID of the scan to aggregate results for
        """
        scan_result = self.db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if not scan_result or scan_result.status != "complete":
            return
        
        # Calculate compliance score based on findings
        total_issues = sum(len(findings) for findings in scan_result.findings.values())
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2
        }
        
        weighted_score = 0
        max_score = 0
        
        for scan_type, findings in scan_result.findings.items():
            for finding in findings:
                severity = finding.get("severity", "low").lower()
                weight = severity_weights.get(severity, 0.1)
                weighted_score += weight
                max_score += 1
        
        if max_score > 0:
            compliance_score = 100 * (1 - (weighted_score / max_score))
        else:
            compliance_score = 100
        
        scan_result.compliance_score = round(compliance_score, 2)
        self.db.commit()
        
        logger.info(f"Updated compliance score for scan {scan_id}: {compliance_score}%")
