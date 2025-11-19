from celery import Task
from src.workers.celery_app import celery_app
from src.integrations.scanning_tools.zap import ZAPScanner
from src.db.session import get_db
from src.db.postgres.models import ScanResults
from src.core.logging import get_logger

logger = get_logger(__name__)

class DASTScanTask(Task):
    _db = None
    
    @property
    def db(self):
        if self._db is None:
            self._db = next(get_db())
        return self._db

@celery_app.task(bind=True, base=DASTScanTask)
def run_dast_scan(self, scan_id: str, repository_url: str) -> dict:
    """
    Runs dynamic application security testing using OWASP ZAP.
    
    Args:
        scan_id: Unique identifier for this scan
        repository_url: URL of the application to scan
        
    Returns:
        Dict containing scan results
    """
    logger.info(f"Starting DAST scan for {repository_url}")
    
    try:
        # Initialize ZAP scanner
        zap_scanner = ZAPScanner()
        
        # Run ZAP scan
        zap_results = zap_scanner.scan_application(repository_url)
        
        # Process results
        processed_results = {
            "zap": zap_results,
            "total_issues": len(zap_results.get("issues", []))
        }
        
        # Update scan results in database
        scan_result = self.db.query(ScanResults).filter(
            ScanResults.scan_id == scan_id
        ).first()
        
        if scan_result:
            current_findings = scan_result.findings or {}
            current_findings["dast"] = processed_results
            scan_result.findings = current_findings
            scan_result.raw_output["dast"] = zap_results.get("raw_output")
            
            self.db.commit()
            
        logger.info(f"DAST scan completed for {repository_url}")
        return processed_results
        
    except Exception as e:
        logger.error(f"DAST scan failed: {str(e)}")
        raise
        
    finally:
        if self._db:
            self._db.close()
