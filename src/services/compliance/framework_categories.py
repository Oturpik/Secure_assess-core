"""
Framework-specific security categories and mappings.
Defines the categories and checks for OWASP Top 10, CIS, and NIST 800-53.
"""

from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class CategoryDef:
    """Definition of a security category within a framework."""
    id: str
    name: str
    description: str
    priority: str  # High, Medium, Low
    checks: List[str]  # List of check IDs this category covers


# OWASP Top 10 2025 Categories
OWASP_CATEGORIES = {
    "A01_BROKEN_ACCESS_CONTROL": CategoryDef(
        id="A01",
        name="Broken Access Control",
        description="Still the leading risk, covering flaws that allow attackers to bypass authorization or gain unauthorized access.",
        priority="High",
        checks=[
            "access_control_bypass",
            "privilege_escalation",
            "authorization_flaws",
            "insecure_direct_object_references",
            "cors_misconfiguration",
            "missing_access_controls"
        ]
    ),
    "A02_CRYPTOGRAPHIC_FAILURES": CategoryDef(
        id="A02",
        name="Cryptographic Failures",
        description="Insecure or outdated encryption practices that expose sensitive data.",
        priority="High",
        checks=[
            "weak_encryption",
            "hardcoded_secrets",
            "insecure_hashing",
            "exposed_credentials",
            "weak_tls",
            "insufficient_data_protection"
        ]
    ),
    "A03_INJECTION": CategoryDef(
        id="A03",
        name="Injection",
        description="Classic input-validation flaws such as SQL, OS, and template injection that remain common across stacks.",
        priority="High",
        checks=[
            "sql_injection",
            "os_command_injection",
            "template_injection",
            "xpath_injection",
            "ldap_injection",
            "code_injection"
        ]
    ),
    "A04_INSECURE_DESIGN": CategoryDef(
        id="A04",
        name="Insecure Design",
        description="Missing or inadequate security controls in the design phase.",
        priority="High",
        checks=[
            "missing_security_controls",
            "insecure_patterns",
            "rate_limiting_absent",
            "missing_authentication",
            "weak_session_management"
        ]
    ),
    "A05_SECURITY_MISCONFIGURATION": CategoryDef(
        id="A05",
        name="Security Misconfiguration",
        description="Covers weak default settings, exposed services, and inconsistent security controls across environments.",
        priority="High",
        checks=[
            "insecure_defaults",
            "exposed_services",
            "missing_security_headers",
            "debug_mode_enabled",
            "default_credentials",
            "unnecessary_features_enabled"
        ]
    ),
    "A06_VULNERABLE_COMPONENTS": CategoryDef(
        id="A06",
        name="Vulnerable and Outdated Components",
        description="Unpatched or outdated software components with known vulnerabilities.",
        priority="High",
        checks=[
            "outdated_dependencies",
            "known_cve_versions",
            "vulnerable_libraries",
            "missing_patches"
        ]
    ),
    "A07_AUTHENTICATION_FAILURES": CategoryDef(
        id="A07",
        name="Authentication Failures",
        description="Issues in login flows, weak password policies, or session handling that lead to unauthorized access.",
        priority="High",
        checks=[
            "weak_authentication",
            "weak_password_policy",
            "session_fixation",
            "missing_mfa",
            "broken_authentication",
            "credential_exposure"
        ]
    ),
    "A08_DATA_INTEGRITY_FAILURES": CategoryDef(
        id="A08",
        name="Software or Data Integrity Failures",
        description="Flaws where code or data can be modified or tampered with, often in update mechanisms or pipelines.",
        priority="High",
        checks=[
            "insecure_deserialization",
            "unsigned_updates",
            "missing_signatures",
            "unsafe_deployment",
            "code_tampering"
        ]
    ),
    "A09_LOGGING_MONITORING_FAILURES": CategoryDef(
        id="A09",
        name="Logging and Monitoring Failures",
        description="Insufficient logging and monitoring to detect security incidents.",
        priority="Medium",
        checks=[
            "missing_logging",
            "insufficient_monitoring",
            "inadequate_alerting",
            "log_tampering",
            "no_audit_trail"
        ]
    ),
    "A10_EXCEPTIONAL_CONDITIONS": CategoryDef(
        id="A10",
        name="Mishandling of Exceptional Conditions",
        description="New for 2025, focused on unsafe error handling and system resilience when failures occur.",
        priority="Medium",
        checks=[
            "unsafe_error_handling",
            "sensitive_info_in_errors",
            "unhandled_exceptions",
            "poor_error_recovery",
            "resource_exhaustion"
        ]
    )
}


# CIS Framework Categories
CIS_CATEGORIES = {
    "CIS_APP_SOFTWARE_SECURITY": CategoryDef(
        id="CIS-AS",
        name="Application Software Security",
        description="Ensures web apps follow secure coding practices, including input validation enforcement, secure API design and dependency vulnerability scanning.",
        priority="High",
        checks=[
            "input_validation",
            "secure_api_design",
            "dependency_scanning",
            "secure_code_practices",
            "buffer_overflow_prevention",
            "format_string_prevention"
        ]
    ),
    "CIS_ACCESS_CONTROL_MANAGEMENT": CategoryDef(
        id="CIS-AC",
        name="Access Control Management",
        description="Enforces role-based authorization, least privilege, session timeouts and protections against privilege escalation via endpoints.",
        priority="High",
        checks=[
            "role_based_access",
            "least_privilege",
            "session_timeout",
            "privilege_escalation_protection",
            "endpoint_authorization",
            "resource_access_controls"
        ]
    )
}


# NIST 800-53 Categories
NIST_CATEGORIES = {
    "NIST_IA": CategoryDef(
        id="NIST-IA",
        name="Identification and Authentication (IA)",
        description="Validates authentication strength, password rules, MFA enforcement, session security.",
        priority="High",
        checks=[
            "user_identification",
            "authentication_strength",
            "password_requirements",
            "mfa_enforcement",
            "session_security",
            "failed_login_attempts",
            "password_expiration",
            "account_lockout"
        ]
    ),
    "NIST_AC": CategoryDef(
        id="NIST-AC",
        name="Access Control (AC)",
        description="Manages authorization, permissions, roles, and access enforcement.",
        priority="High",
        checks=[
            "access_control_policy",
            "least_privilege_enforcement",
            "role_based_access",
            "separation_of_duties",
            "access_enforcement",
            "boundary_protection"
        ]
    ),
    "NIST_AU": CategoryDef(
        id="NIST-AU",
        name="Audit and Accountability (AU)",
        description="Logging, monitoring, and audit trail management.",
        priority="Medium",
        checks=[
            "audit_logging",
            "log_protection",
            "log_retention",
            "audit_review",
            "accountability",
            "tamper_detection"
        ]
    ),
    "NIST_SI": CategoryDef(
        id="NIST-SI",
        name="System and Information Integrity (SI)",
        description="Malware protection, security updates, and system monitoring.",
        priority="High",
        checks=[
            "malware_protection",
            "security_updates",
            "system_monitoring",
            "information_integrity",
            "flaw_remediation",
            "security_testing"
        ]
    ),
    "NIST_SC": CategoryDef(
        id="NIST-SC",
        name="System and Communications Protection (SC)",
        description="Cryptography, encryption, and secure communications.",
        priority="High",
        checks=[
            "encryption_in_transit",
            "encryption_at_rest",
            "key_management",
            "cryptographic_controls",
            "secure_protocols",
            "boundary_protection"
        ]
    )
}


class FrameworkType(str, Enum):
    """Available security frameworks."""
    OWASP = "OWASP"
    CIS = "CIS"
    NIST = "NIST"


# Map framework types to their categories
FRAMEWORK_MAPPINGS = {
    FrameworkType.OWASP: OWASP_CATEGORIES,
    FrameworkType.CIS: CIS_CATEGORIES,
    FrameworkType.NIST: NIST_CATEGORIES
}


def get_categories_for_framework(framework_name: str) -> Dict[str, CategoryDef]:
    """
    Get all categories for a specific framework.
    
    Args:
        framework_name: Name of the framework (OWASP, CIS, NIST)
        
    Returns:
        Dict mapping category IDs to CategoryDef objects
    """
    try:
        framework_type = FrameworkType(framework_name.upper())
        return FRAMEWORK_MAPPINGS.get(framework_type, {})
    except ValueError:
        return {}


def get_category(framework_name: str, category_id: str) -> Optional[CategoryDef]:
    """
    Get a specific category for a framework.
    
    Args:
        framework_name: Name of the framework
        category_id: ID of the category
        
    Returns:
        CategoryDef if found, None otherwise
    """
    categories = get_categories_for_framework(framework_name)
    return next((cat for cat in categories.values() if cat.id == category_id), None)


def get_checks_for_category(framework_name: str, category_id: str) -> List[str]:
    """
    Get all checks that apply to a specific category.
    
    Args:
        framework_name: Name of the framework
        category_id: ID of the category
        
    Returns:
        List of check IDs
    """
    category = get_category(framework_name, category_id)
    return category.checks if category else []


def get_all_framework_names() -> List[str]:
    """Get list of all available frameworks."""
    return [fw.value for fw in FrameworkType]


def map_scanner_finding_to_categories(
    framework_name: str,
    finding_type: str,
    severity: str
) -> List[str]:
    """
    Map a scanner finding to relevant framework categories.
    
    Args:
        framework_name: Name of the framework
        finding_type: Type of finding (e.g., 'sql_injection', 'weak_encryption')
        severity: Severity level of the finding
        
    Returns:
        List of category IDs that this finding maps to
    """
    categories = get_categories_for_framework(framework_name)
    matching_categories = []
    
    for category_id, category_def in categories.items():
        if finding_type in category_def.checks:
            matching_categories.append(category_def.id)
    
    return matching_categories
