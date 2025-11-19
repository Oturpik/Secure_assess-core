#!/usr/bin/env python3
"""
Direct test of framework-aware SAST scanning without Celery workers.
This test calls the CategoryCheckRunner directly to verify the framework categorization works.
"""

import sys
import os
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db.session import SyncSessionLocal
from src.db.postgres.models import Framework, Control, ScanResult
from src.services.scanning.category_checker import CategoryCheckRunner
from src.services.compliance.framework_categories import OWASP_CATEGORIES, CIS_CATEGORIES, NIST_CATEGORIES
from datetime import datetime
import uuid

def test_framework_categorization():
    """Test that framework categories are properly retrieved and findings are categorized"""
    
    db = SyncSessionLocal()
    
    try:
        # Get OWASP framework
        framework = db.query(Framework).filter(Framework.name == "OWASP").first()
        if not framework:
            print("❌ OWASP framework not found in database")
            return False
            
        print(f"✅ Found OWASP framework (ID: {framework.id})")
        
        # Get controls (categories)
        controls = db.query(Control).filter(Control.framework_id == framework.id).all()
        print(f"✅ Found {len(controls)} OWASP categories in database:")
        for ctrl in controls:
            print(f"   - {ctrl.control_id}: {ctrl.title}")
        
        if len(controls) != 10:
            print(f"❌ Expected 10 OWASP categories, got {len(controls)}")
            return False
        
        # Create sample findings (like Bandit + Semgrep would produce)
        sample_findings = [
            {
                "id": "B303",  # Bandit
                "type": "sql_injection",
                "severity": "high",
                "message": "Use of insecure MD5 hash",
                "file": "src/main.py",
                "line": 42
            },
            {
                "id": "B608",  # Bandit
                "type": "hardcoded_sql",
                "severity": "critical",
                "message": "Possible SQL injection vector through string-based query construction",
                "file": "src/api/endpoints.py",
                "line": 105
            },
            {
                "id": "hardcoded-secret",  # Semgrep
                "type": "hardcoded_secret",
                "severity": "critical",
                "message": "Hardcoded secret detected",
                "file": "src/config.py",
                "line": 15
            }
        ]
        
        print(f"\n✅ Created {len(sample_findings)} sample findings for categorization")
        
        # Test CategoryCheckRunner
        checker = CategoryCheckRunner(db=db)
        
        print("\n🔄 Categorizing findings using CategoryCheckRunner...")
        findings_by_category = checker.categorize_findings(
            framework_name="OWASP",
            findings={"bandit": sample_findings}
        )
        
        print(f"✅ Categorized findings:")
        for category_id, findings in findings_by_category.items():
            print(f"   {category_id}: {len(findings)} finding(s)")
            for finding in findings:
                print(f"      - {finding.get('message', 'Unknown')}")
        
        # Test scoring
        print("\n🔄 Calculating category scores...")
        category_scores = checker.calculate_category_scores(
            framework_name="OWASP",
            categorized_findings=findings_by_category
        )
        
        print(f"✅ Category scores:")
        for category_id, score_data in category_scores.items():
            print(f"   {category_id}: {score_data.get('score', 0)}%")
        
        # Test overall score
        print("\n🔄 Calculating overall compliance score...")
        overall_score = checker.calculate_overall_score(
            category_scores=category_scores
        )
        print(f"✅ Overall compliance score: {overall_score}%")
        
        # Test recommendations
        print("\n🔄 Getting category recommendations...")
        recommendations = checker.get_category_recommendations(
            framework_name="OWASP",
            categorized_findings=findings_by_category
        )
        print(f"✅ Recommendations for {len(recommendations)} categories:")
        for i, (category_id, rec_list) in enumerate(recommendations.items()):
            if i >= 3:  # Show first 3 categories
                break
            print(f"   - {category_id}: {len(rec_list) if isinstance(rec_list, list) else 1} recommendations")
        
        # Verify the data structure
        print("\n" + "="*60)
        print("TEST RESULTS")
        print("="*60)
        print(f"✅ Framework name: {framework.name}")
        print(f"✅ Framework version: {framework.version}")
        print(f"✅ Total categories: {len(controls)}")
        print(f"✅ Findings categorized: {sum(len(f) for f in findings_by_category.values())}/{len(sample_findings)}")
        print(f"✅ Categories with findings: {len(findings_by_category)}")
        print(f"✅ Overall compliance score: {overall_score}%")
        
        print("\n✅ ALL TESTS PASSED!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    success = test_framework_categorization()
    sys.exit(0 if success else 1)
