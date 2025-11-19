"""
Framework-specific security check runner.
Maps scanner findings to framework categories and scores compliance.
"""

from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from src.db.postgres.models import ScanResult, Framework, Control
from src.services.compliance.framework_categories import (
    get_categories_for_framework,
    map_scanner_finding_to_categories,
    get_checks_for_category
)
from src.core.logging import get_logger

logger = get_logger(__name__)


class CategoryCheckRunner:
    """Runs framework-specific security checks per category."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def categorize_findings(
        self,
        framework_name: str,
        findings: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Organize scanner findings into framework categories.
        
        Args:
            framework_name: Name of the framework (OWASP, CIS, NIST)
            findings: Raw findings from scanners
                {
                    "bandit": [...],
                    "semgrep": [...]
                }
        
        Returns:
            Findings organized by category:
            {
                "A01": [...],  # Category ID -> findings
                "A02": [...]
            }
        """
        categorized = {}
        
        # Process Bandit findings
        for finding in findings.get("bandit", []):
            categories = self._map_bandit_to_categories(framework_name, finding)
            for category_id in categories:
                if category_id not in categorized:
                    categorized[category_id] = []
                categorized[category_id].append({
                    "tool": "bandit",
                    "finding": finding,
                    "severity": finding.get("severity", "unknown").upper(),
                    "file": finding.get("file"),
                    "line": finding.get("line")
                })
        
        # Process Semgrep findings
        for finding in findings.get("semgrep", []):
            categories = self._map_semgrep_to_categories(framework_name, finding)
            for category_id in categories:
                if category_id not in categorized:
                    categorized[category_id] = []
                categorized[category_id].append({
                    "tool": "semgrep",
                    "finding": finding,
                    "severity": finding.get("severity", "unknown").upper(),
                    "file": finding.get("file"),
                    "line": finding.get("line")
                })
        
        return categorized
    
    def _map_bandit_to_categories(
        self,
        framework_name: str,
        finding: Dict[str, Any]
    ) -> List[str]:
        """Map a Bandit finding to framework categories."""
        issue_type = finding.get("type", "").lower()
        severity = finding.get("severity", "").lower()
        
        # Bandit test ID mapping to check types
        test_mappings = {
            "hardcoded_password": "hardcoded_secrets",
            "hardcoded_sql_string": "sql_injection",
            "hardcoded_temp_file": "insecure_defaults",
            "assert_used": "security_misconfiguration",
            "exec_used": "code_injection",
            "eval_used": "code_injection",
            "subprocess": "os_command_injection",
            "start_process_with_a_shell": "os_command_injection",
            "start_process_with_partial_path": "os_command_injection",
            "suspicious_non_cryptographic_random_usage": "weak_encryption",
            "use_of_input_instead_of_raw_input": "input_validation",
            "import_telnetlib": "insecure_protocols",
            "try_except_pass": "unsafe_error_handling",
            "except_pass": "unsafe_error_handling",
            "bad_file_permissions": "insecure_defaults",
            "flask_debug_true": "debug_mode_enabled",
            "insecure_hash_function": "weak_encryption",
            "insecure_random_function": "weak_encryption",
            "paramiko_calls": "weak_encryption",
            "request_with_no_cert_validation": "insecure_protocols",
            "use_of_mako_templates": "template_injection",
            "jinja2_autoescape_false": "template_injection",
        }
        
        check_type = test_mappings.get(issue_type, issue_type)
        categories = map_scanner_finding_to_categories(
            framework_name,
            check_type,
            severity
        )
        
        return categories
    
    def _map_semgrep_to_categories(
        self,
        framework_name: str,
        finding: Dict[str, Any]
    ) -> List[str]:
        """Map a Semgrep finding to framework categories."""
        rule_id = finding.get("rule_id", "").lower()
        message = finding.get("message", "").lower()
        severity = finding.get("severity", "").lower()
        
        # Common Semgrep rule patterns to check types
        check_type = None
        
        if any(x in rule_id for x in ["sql", "injection"]):
            check_type = "sql_injection"
        elif any(x in rule_id for x in ["auth", "password", "credential"]):
            check_type = "weak_authentication"
        elif any(x in rule_id for x in ["crypto", "encrypt", "hash"]):
            check_type = "weak_encryption"
        elif any(x in rule_id for x in ["access", "control", "permission"]):
            check_type = "access_control_bypass"
        elif any(x in rule_id for x in ["xxe", "xml", "parse"]):
            check_type = "injection"
        elif any(x in rule_id for x in ["xss", "script", "html"]):
            check_type = "injection"
        elif any(x in rule_id for x in ["command", "exec", "os"]):
            check_type = "os_command_injection"
        elif any(x in rule_id for x in ["error", "exception", "logging"]):
            check_type = "unsafe_error_handling"
        elif any(x in rule_id for x in ["default", "config", "setting"]):
            check_type = "insecure_defaults"
        else:
            check_type = rule_id
        
        categories = map_scanner_finding_to_categories(
            framework_name,
            check_type,
            severity
        )
        
        return categories
    
    def calculate_category_scores(
        self,
        framework_name: str,
        categorized_findings: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Calculate compliance score for each category.
        
        Args:
            framework_name: Name of the framework
            categorized_findings: Findings organized by category
        
        Returns:
            Score breakdown by category:
            {
                "A01": {
                    "score": 75.0,
                    "total_issues": 2,
                    "critical": 0,
                    "high": 1,
                    "medium": 1,
                    "low": 0
                }
            }
        """
        categories = get_categories_for_framework(framework_name)
        category_scores = {}
        
        for category_id, category_def in categories.items():
            findings = categorized_findings.get(category_def.id, [])
            
            # Count issues by severity
            severity_counts = {
                "CRITICAL": len([f for f in findings if f["severity"] == "CRITICAL"]),
                "HIGH": len([f for f in findings if f["severity"] == "HIGH"]),
                "MEDIUM": len([f for f in findings if f["severity"] == "MEDIUM"]),
                "LOW": len([f for f in findings if f["severity"] == "LOW"])
            }
            
            total_issues = sum(severity_counts.values())
            
            # Calculate score: 100 - (deductions based on issues)
            # Critical = -25, High = -15, Medium = -8, Low = -3
            score = 100.0
            score -= severity_counts["CRITICAL"] * 25
            score -= severity_counts["HIGH"] * 15
            score -= severity_counts["MEDIUM"] * 8
            score -= severity_counts["LOW"] * 3
            
            # Ensure score is between 0 and 100
            score = max(0.0, min(100.0, score))
            
            category_scores[category_def.id] = {
                "category": category_def.name,
                "score": round(score, 2),
                "total_issues": total_issues,
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
                "priority": category_def.priority
            }
        
        return category_scores
    
    def calculate_overall_score(
        self,
        category_scores: Dict[str, Dict[str, Any]]
    ) -> float:
        """
        Calculate overall compliance score from category scores.
        Weighted by priority: High = 50%, Medium = 35%, Low = 15%
        
        Args:
            category_scores: Category scores breakdown
        
        Returns:
            Overall compliance score (0-100)
        """
        priority_weights = {
            "High": 0.50,
            "Medium": 0.35,
            "Low": 0.15
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for category_id, score_data in category_scores.items():
            priority = score_data.get("priority", "Medium")
            weight = priority_weights.get(priority, 0.35)
            score = score_data.get("score", 0)
            
            weighted_sum += score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 100.0
        
        overall_score = weighted_sum / total_weight
        return round(overall_score, 2)
    
    def get_category_recommendations(
        self,
        framework_name: str,
        categorized_findings: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, List[str]]:
        """
        Generate remediation recommendations per category.
        
        Args:
            framework_name: Name of the framework
            categorized_findings: Findings organized by category
        
        Returns:
            Recommendations per category
        """
        categories = get_categories_for_framework(framework_name)
        recommendations = {}
        
        for category_id, category_def in categories.items():
            findings = categorized_findings.get(category_def.id, [])
            
            if not findings:
                recommendations[category_def.id] = ["No issues found in this category."]
                continue
            
            recs = []
            
            # Generic recommendations based on category
            if "OWASP" in framework_name:
                if "A01" in category_id:
                    recs.append("Implement role-based access control (RBAC) throughout the application")
                    recs.append("Enforce principle of least privilege for all users and service accounts")
                    recs.append("Regularly audit and test access controls")
                elif "A02" in category_id:
                    recs.append("Use strong, up-to-date encryption standards (TLS 1.3+, AES-256)")
                    recs.append("Implement secure key management practices")
                    recs.append("Never hardcode secrets or credentials in code")
                elif "A03" in category_id:
                    recs.append("Use parameterized queries and prepared statements")
                    recs.append("Implement input validation and sanitization")
                    recs.append("Apply principle of least privilege to database accounts")
                elif "A07" in category_id:
                    recs.append("Enforce strong password policies with complexity requirements")
                    recs.append("Implement multi-factor authentication (MFA)")
                    recs.append("Use secure session management with timeouts")
            
            elif "CIS" in framework_name:
                if "AC" in category_id:
                    recs.append("Implement and enforce role-based access control (RBAC)")
                    recs.append("Configure session timeouts and re-authentication")
                    recs.append("Log and monitor all access attempts")
                elif "AS" in category_id:
                    recs.append("Conduct regular security code reviews")
                    recs.append("Implement static and dynamic security testing")
                    recs.append("Scan for vulnerable dependencies regularly")
            
            elif "NIST" in framework_name:
                if "IA" in category_id:
                    recs.append("Strengthen authentication mechanisms with MFA or equivalent")
                    recs.append("Enforce password complexity and expiration policies")
                    recs.append("Implement account lockout after failed attempts")
                elif "AC" in category_id:
                    recs.append("Establish and enforce access control policy")
                    recs.append("Implement least privilege for all accounts")
                    recs.append("Review and audit access controls periodically")
                elif "SI" in category_id:
                    recs.append("Keep systems and software up to date with security patches")
                    recs.append("Implement endpoint protection and malware scanning")
                    recs.append("Monitor systems for security anomalies")
            
            if not recs:
                recs.append(f"Review {category_def.name} requirements and address findings")
            
            recommendations[category_def.id] = recs
        
        return recommendations
