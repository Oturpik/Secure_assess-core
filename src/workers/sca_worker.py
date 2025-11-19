from celery import Task
from src.workers.celery_app import celery_app
from src.integrations.scanning_tools.dependency_check import DependencyCheck
from src.db.session import get_db
from src.db.postgres.models import ScanResults
from src.core.logging import get_logger

logger = get_logger(__name__)

class SCAScanTask(Task):
    _db = None
    
    @property
    def db(self):
        if self._db is None:
            self._db = next(get_db())
        return self._db

@celery_app.task(bind=True, base=SCAScanTask)
def run_sca_scan(self, scan_id: str, repository_url: str, branch: str) -> dict:
    """
    Runs software composition analysis using OWASP Dependency Check.
    
    Args:
        scan_id: Unique identifier for this scan
        repository_url: URL of the repository to scan
        branch: Branch to scan
        
    Returns:
        Dict containing scan results
    """
    logger.info(f"Starting SCA scan for {repository_url}:{branch}")
    
    try:
        # Initialize dependency checker
        dep_checker = DependencyCheck()
        
        # Run dependency scan
        dep_results = dep_checker.scan_repository(
            repository_url=repository_url,
            branch=branch
        )
        
        # Process results
        processed_results = {
            "dependency_check": dep_results,
            "total_vulnerabilities": len(dep_results.get("vulnerabilities", [])),
            "critical_vulnerabilities": len([
                v for v in dep_results.get("vulnerabilities", [])
                if v.get("severity", "").lower() == "critical"
            ])
        }
        
        # Update scan results in database
        scan_result = self.db.query(ScanResults).filter(
            ScanResults.scan_id == scan_id
        ).first()
        
        if scan_result:
            current_findings = scan_result.findings or {}
            current_findings["sca"] = processed_results
            scan_result.findings = current_findings
            scan_result.raw_output["sca"] = dep_results.get("raw_output")
            
            self.db.commit()
            
        logger.info(f"SCA scan completed for {repository_url}:{branch}")
        return processed_results
        
    except Exception as e:
        logger.error(f"SCA scan failed: {str(e)}")
        raise
        
    finally:
        if self._db:
            self._db.close()
