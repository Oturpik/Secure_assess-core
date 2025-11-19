from celery import Task
from src.workers.celery_app import celery_app
from src.integrations.scanning_tools.bandit import BanditScanner
from src.integrations.scanning_tools.semgrep import SemgrepScanner
from src.db.session import get_db
from src.db.postgres.models import ScanResult
from src.core.logging import get_logger

logger = get_logger(__name__)

class SASTScanTask(Task):
    _db = None
    
    @property
    def db(self):
        if self._db is None:
            self._db = next(get_db())
        return self._db

@celery_app.task(bind=True, base=SASTScanTask)
def run_sast_scan(self, scan_id: str, repository_url: str, branch: str) -> dict:
    """
    Runs static application security testing using multiple tools.
    
    Args:
        scan_id: Unique identifier for this scan
        repository_url: URL of the repository to scan
        branch: Branch to scan
        
    Returns:
        Dict containing scan results
    """
    logger.info(f"Starting SAST scan for {repository_url}:{branch}")
    
    try:
        # Get scan configuration
        scan_result = self.db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if not scan_result:
            raise ValueError(f"Scan {scan_id} not found")
            
        # Load framework-specific rules
        from src.services.scanning.rules_manager import RulesManager
        rules_manager = RulesManager(self.db)
        framework_rules = rules_manager.get_framework_rules(scan_result.framework_id)
        
        # Initialize scanners
        bandit_scanner = BanditScanner()
        semgrep_scanner = SemgrepScanner()
        
        # Run Bandit scan with framework rules
        bandit_results = bandit_scanner.scan_repository(
            repository_url=repository_url,
            branch=branch,
            custom_rules=framework_rules["bandit"]
        )
        
        # Run Semgrep scan with framework rules
        semgrep_results = semgrep_scanner.scan_repository(
            repository_url=repository_url,
            branch=branch,
            rules=framework_rules["semgrep"]
        )
        
        # Map findings to known vulnerabilities
        from src.services.scanning.vulnerability_mapper import VulnerabilityMapper
        mapper = VulnerabilityMapper(self.db)
        
        mapped_findings = []
        
        # Map Bandit findings
        for finding in bandit_results.get("issues", []):
            matches = mapper.map_bandit_finding(finding)
            if matches:
                mapped_findings.append({
                    "tool": "bandit",
                    "finding": finding,
                    "matches": matches,
                    "controls": [
                        control
                        for match in matches
                        for control in mapper.map_to_controls(match["vulnerability_id"])
                    ]
                })
        
        # Map Semgrep findings
        for finding in semgrep_results.get("issues", []):
            matches = mapper.map_semgrep_finding(finding)
            if matches:
                mapped_findings.append({
                    "tool": "semgrep",
                    "finding": finding,
                    "matches": matches,
                    "controls": [
                        control
                        for match in matches
                        for control in mapper.map_to_controls(match["vulnerability_id"])
                    ]
                })
        
        # Combine results
        combined_results = {
            "bandit": bandit_results,
            "semgrep": semgrep_results,
            "total_issues": len(bandit_results.get("issues", [])) + 
                          len(semgrep_results.get("issues", [])),
            "mapped_findings": mapped_findings,
            "framework_matches": {
                "total_mapped": len(mapped_findings),
                "high_confidence": len([f for f in mapped_findings 
                    if any(m["confidence"] > 0.8 for m in f["matches"])])
            }
        }
        
        # Update scan results in database
        scan_result = self.db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if scan_result:
            current_findings = scan_result.findings or {}
            current_findings["sast"] = combined_results
            scan_result.findings = current_findings
            scan_result.raw_output["sast"] = {
                "bandit": bandit_results.get("raw_output"),
                "semgrep": semgrep_results.get("raw_output")
            }
            
            self.db.commit()
            
        logger.info(f"SAST scan completed for {repository_url}:{branch}")
        return combined_results
        
    except Exception as e:
        logger.error(f"SAST scan failed: {str(e)}")
        raise
        
    finally:
        if self._db:
            self._db.close()
