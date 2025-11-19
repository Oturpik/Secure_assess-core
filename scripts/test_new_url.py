#!/usr/bin/env python3
"""
Complete workflow for testing a new repository URL with framework-aware scanning.

This script demonstrates the end-to-end process:
1. Submit a new repository URL for scanning
2. Select a compliance framework (OWASP, CIS, or NIST)
3. Monitor scan progress
4. Retrieve and display categorized results
5. Show compliance scores and remediation recommendations
"""

import sys
import os
import time
import json
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db.session import SyncSessionLocal
from src.db.postgres.models import Framework, Scan, ScanResult
from src.services.scanning.orchestrator import ScanOrchestrator
from sqlalchemy import create_engine, text


def list_available_frameworks():
    """Show available frameworks to choose from."""
    db = SyncSessionLocal()
    try:
        frameworks = db.query(Framework).all()
        print("\n" + "="*60)
        print("AVAILABLE COMPLIANCE FRAMEWORKS")
        print("="*60)
        for fw in frameworks:
            print(f"\n📋 {fw.name} (ID: {fw.id})")
            print(f"   Version: {fw.version}")
            print(f"   Categories: {len(fw.controls)}")
            categories = [f"{c.control_id}: {c.title}" for c in fw.controls[:3]]
            for cat in categories:
                print(f"     - {cat}")
            if len(fw.controls) > 3:
                print(f"     ... and {len(fw.controls) - 3} more")
        return frameworks
    finally:
        db.close()


def submit_scan(repository_url: str, branch: str = "main", framework_id: int = 1):
    """
    Step 1: Submit a new scan request.
    
    Args:
        repository_url: Git repository URL (e.g., https://github.com/user/repo.git)
        branch: Branch to scan (default: main)
        framework_id: Framework ID (1=OWASP, 2=CIS, 3=NIST)
    
    Returns:
        scan_id: Unique identifier for the scan
    """
    db = SyncSessionLocal()
    try:
        print("\n" + "="*60)
        print("STEP 1: SUBMITTING SCAN REQUEST")
        print("="*60)
        print(f"📍 Repository: {repository_url}")
        print(f"🌿 Branch: {branch}")
        print(f"📋 Framework: {framework_id}")
        
        orchestrator = ScanOrchestrator(db=db)
        scan_id = orchestrator.initiate_scan(
            repository_url=repository_url,
            branch=branch,
            framework_id=framework_id,
            scan_types=["sast"],
            priority=5
        )
        
        print(f"\n✅ Scan submitted successfully!")
        print(f"   Scan ID: {scan_id}")
        return scan_id
    
    except Exception as e:
        print(f"❌ Failed to submit scan: {str(e)}")
        return None
    finally:
        db.close()


def monitor_scan_progress(scan_id: str, max_wait_seconds: int = 300):
    """
    Step 2: Monitor scan progress.
    
    Shows real-time updates as the scan progresses.
    """
    db = SyncSessionLocal()
    try:
        print("\n" + "="*60)
        print("STEP 2: MONITORING SCAN PROGRESS")
        print("="*60)
        
        orchestrator = ScanOrchestrator(db=db)
        start_time = time.time()
        check_count = 0
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > max_wait_seconds:
                print(f"\n⏱️  Timeout: Scan did not complete within {max_wait_seconds} seconds")
                print("    This is normal for large repositories - the scan may still be processing")
                return None
            
            check_count += 1
            status_info = orchestrator.get_scan_status(scan_id)
            status = status_info['status']
            
            # Display progress
            print(f"\r⏳ Check #{check_count} (Elapsed: {int(elapsed)}s) - Status: {status.upper()}", end="", flush=True)
            
            if status == "complete":
                print("\n\n✅ Scan completed successfully!")
                return status_info
            elif status == "failed":
                print("\n\n❌ Scan failed!")
                return status_info
            
            # Wait before next check
            time.sleep(10)
    
    finally:
        db.close()


def display_scan_results(scan_results: dict):
    """
    Step 3: Display scan results in a user-friendly format.
    """
    print("\n" + "="*60)
    print("STEP 3: SCAN RESULTS")
    print("="*60)
    
    scan_id = scan_results.get('scan_id')
    status = scan_results.get('status')
    compliance_score = scan_results.get('compliance_score', 0)
    
    print(f"\n📊 OVERALL COMPLIANCE SCORE: {compliance_score}%")
    
    # Display findings summary
    findings = scan_results.get('findings', {})
    print(f"\n📋 FINDINGS SUMMARY:")
    if isinstance(findings, dict):
        for severity, count in findings.items():
            if isinstance(count, int):
                icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡" if severity == "medium" else "🟢"
                print(f"   {icon} {severity.upper()}: {count}")


def display_categorized_results(scan_id: str, framework_name: str = "OWASP"):
    """
    Step 4: Display results broken down by framework categories.
    """
    db = SyncSessionLocal()
    try:
        print("\n" + "="*60)
        print(f"STEP 4: FRAMEWORK-SPECIFIC RESULTS ({framework_name})")
        print("="*60)
        
        # Query scan result
        scan_result = db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if not scan_result:
            print(f"❌ Scan result not found for ID: {scan_id}")
            return
        
        # Display category scores
        if scan_result.category_scores:
            print(f"\n📊 CATEGORY SCORES ({framework_name}):")
            category_scores = scan_result.category_scores
            
            # Sort by score (lowest first - most concerning)
            sorted_categories = sorted(
                category_scores.items(),
                key=lambda x: x[1],
                reverse=False
            )
            
            for category_id, score in sorted_categories:
                # Color code the scores
                if score >= 90:
                    status_icon = "✅"
                elif score >= 70:
                    status_icon = "⚠️ "
                elif score >= 50:
                    status_icon = "🔴"
                else:
                    status_icon = "🚨"
                
                bar_length = int(score / 10)
                bar = "█" * bar_length + "░" * (10 - bar_length)
                print(f"   {status_icon} {category_id}: {score:5.1f}% [{bar}]")
        
        # Display findings by category
        if scan_result.findings_by_category:
            print(f"\n🔍 FINDINGS BY CATEGORY:")
            findings_by_category = scan_result.findings_by_category
            
            for category_id, findings in findings_by_category.items():
                if findings and len(findings) > 0:
                    print(f"\n   📌 {category_id}: {len(findings)} finding(s)")
                    for finding in findings[:2]:  # Show first 2
                        severity = finding.get('severity', 'unknown').upper()
                        message = finding.get('message', 'Unknown issue')
                        print(f"      • {severity}: {message}")
                    if len(findings) > 2:
                        print(f"      ... and {len(findings) - 2} more")
        
        # Display scanned categories
        if scan_result.scanned_categories:
            print(f"\n✓ CATEGORIES SCANNED: {len(scan_result.scanned_categories)}")
            categories_list = ", ".join(scan_result.scanned_categories[:5])
            if len(scan_result.scanned_categories) > 5:
                categories_list += f", ... and {len(scan_result.scanned_categories) - 5} more"
            print(f"   {categories_list}")
    
    finally:
        db.close()


def export_results(scan_id: str, output_file: str = None):
    """
    Step 5: Export results to JSON file.
    """
    db = SyncSessionLocal()
    try:
        print("\n" + "="*60)
        print("STEP 5: EXPORTING RESULTS")
        print("="*60)
        
        scan_result = db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).first()
        
        if not scan_result:
            print(f"❌ Scan result not found for ID: {scan_id}")
            return
        
        # Prepare export data
        export_data = {
            "scan_id": scan_result.scan_id,
            "framework_id": scan_result.framework_id,
            "repository_url": scan_result.repository_url,
            "branch": scan_result.branch,
            "scan_date": scan_result.scan_date.isoformat() if scan_result.scan_date else None,
            "status": scan_result.status,
            "compliance_score": scan_result.compliance_score,
            "findings_by_category": scan_result.findings_by_category,
            "category_scores": scan_result.category_scores,
            "scanned_categories": scan_result.scanned_categories,
            "raw_findings": scan_result.findings
        }
        
        # Save to file
        if output_file is None:
            output_file = f"scan_results_{scan_id[:8]}.json"
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"✅ Results exported to: {output_file}")
        return output_file
    
    finally:
        db.close()


def print_usage():
    """Print usage instructions."""
    print("""
╔════════════════════════════════════════════════════════════╗
║   FRAMEWORK-AWARE SECURITY SCANNING - COMPLETE WORKFLOW    ║
╚════════════════════════════════════════════════════════════╝

USAGE:
    python test_new_url.py <REPOSITORY_URL> [BRANCH] [FRAMEWORK_ID]

EXAMPLES:

    # Test with OWASP (default)
    python test_new_url.py https://github.com/user/repo.git

    # Test specific branch with CIS framework
    python test_new_url.py https://github.com/user/repo.git develop 2

    # Test with NIST framework
    python test_new_url.py https://github.com/user/repo.git main 3

FRAMEWORKS:
    1 = OWASP Top 10 (10 categories: A01-A10)
    2 = CIS Framework (2 categories: CIS-AS, CIS-AC)
    3 = NIST 800-53 (5 categories: NIST-IA, AC, AU, SI, SC)

WORKFLOW:
    1. Submit the repository URL for scanning
    2. Monitor progress (scan runs automatically)
    3. View results with framework-specific categorization
    4. Export results to JSON for integration with frontend

NOTES:
    - Scans typically take 1-3 minutes depending on repository size
    - Results are categorized by your selected framework
    - Compliance scores are calculated per category
    - All results are stored in the database for later retrieval
    """)


def main():
    """Main workflow."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Test a new repository URL with framework-aware scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "repository_url",
        help="Git repository URL (e.g., https://github.com/user/repo.git)"
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to scan (default: main)"
    )
    parser.add_argument(
        "--framework",
        type=int,
        default=1,
        choices=[1, 2, 3],
        help="Framework ID: 1=OWASP, 2=CIS, 3=NIST (default: 1)"
    )
    parser.add_argument(
        "--export",
        help="Export results to specified JSON file"
    )
    parser.add_argument(
        "--list-frameworks",
        action="store_true",
        help="List available frameworks and exit"
    )
    
    args = parser.parse_args()
    
    # List frameworks if requested
    if args.list_frameworks:
        list_available_frameworks()
        return 0
    
    # Main workflow
    print("\n🚀 STARTING FRAMEWORK-AWARE SECURITY SCAN")
    print(f"   Repository: {args.repository_url}")
    print(f"   Branch: {args.branch}")
    print(f"   Framework ID: {args.framework}")
    
    # Step 1: Submit scan
    scan_id = submit_scan(
        repository_url=args.repository_url,
        branch=args.branch,
        framework_id=args.framework
    )
    
    if not scan_id:
        return 1
    
    # Step 2: Monitor progress
    results = monitor_scan_progress(scan_id, max_wait_seconds=300)
    
    if not results:
        print("\n⚠️  Could not retrieve results, but scan may still be processing")
        print(f"    Check status later with scan ID: {scan_id}")
        return 1
    
    # Step 3: Display results
    display_scan_results(results)
    
    # Step 4: Display framework-specific results
    display_categorized_results(scan_id, f"Framework {args.framework}")
    
    # Step 5: Export if requested
    if args.export:
        export_results(scan_id, args.export)
    
    print("\n" + "="*60)
    print("✅ WORKFLOW COMPLETE!")
    print("="*60)
    print(f"\n📌 Scan ID for reference: {scan_id}")
    print("\n💡 Next Steps:")
    print("   - Review the categorized findings above")
    print("   - Address high-severity issues in priority order")
    print("   - Re-scan after fixes to verify improvements")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
