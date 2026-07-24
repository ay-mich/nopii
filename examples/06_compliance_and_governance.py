#!/usr/bin/env python3
"""
NoPII Compliance and Governance Examples

This example demonstrates how to configure NoPII for various compliance frameworks
including GDPR, HIPAA, CCPA, and other regulatory requirements. It covers:

1. Compliance-specific policy configurations
2. Regulatory audit reporting
3. Data subject rights implementation
4. Breach detection and notification
5. Governance frameworks and controls
6. Automated compliance monitoring

Run this script to see comprehensive compliance examples in action.
"""

import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

# Import NoPII components
from nopii import NoPIIClient, Policy, Rule

# %%
print("🏛️ NoPII Compliance and Governance Examples")
print("=" * 50)

# %%
print("\n📋 GDPR Compliance Configuration:")


class GDPRComplianceLevel(Enum):
    """GDPR compliance levels"""

    STRICT = "strict"
    STANDARD = "standard"
    MINIMAL = "minimal"


@dataclass
class GDPRConfiguration:
    """GDPR-specific configuration"""

    compliance_level: GDPRComplianceLevel
    data_subject_rights_enabled: bool = True
    right_to_be_forgotten: bool = True
    data_portability: bool = True
    consent_tracking: bool = True
    breach_notification_hours: int = 72
    dpo_contact: str = "dpo@company.com"
    lawful_basis: List[str] = None

    def __post_init__(self):
        if self.lawful_basis is None:
            self.lawful_basis = ["consent", "legitimate_interest", "contract"]


def create_gdpr_policy(config: GDPRConfiguration) -> Policy:
    """Create a GDPR-compliant policy"""

    # Base rules for all GDPR compliance levels
    base_rules = [
        Rule(
            match="email",
            action="hash",
            override_confidence=0.8,
        ),
        Rule(
            match="phone",
            action="mask",
            override_confidence=0.8,
        ),
        Rule(
            match="person_name",
            action="tokenize"
            if config.compliance_level == GDPRComplianceLevel.STRICT
            else "mask",
            override_confidence=0.9,
        ),
    ]

    # Additional rules for strict compliance
    if config.compliance_level == GDPRComplianceLevel.STRICT:
        strict_rules = [
            Rule(match="ip", action="hash", override_confidence=0.7),
            Rule(match="location", action="nullify", override_confidence=0.8),
        ]
        base_rules.extend(strict_rules)

    # Create policy with GDPR compliance
    policy = Policy(
        name=f"gdpr_policy_{config.compliance_level.value}",
        description=f"GDPR compliance policy - {config.compliance_level.value} level",
        rules=base_rules,
        default_action="mask",
    )

    return policy


# Create different GDPR compliance configurations
gdpr_strict_config = GDPRConfiguration(
    compliance_level=GDPRComplianceLevel.STRICT,
    breach_notification_hours=24,  # Stricter than required
    lawful_basis=["explicit_consent", "vital_interests"],
)

gdpr_standard_config = GDPRConfiguration(compliance_level=GDPRComplianceLevel.STANDARD)

gdpr_minimal_config = GDPRConfiguration(
    compliance_level=GDPRComplianceLevel.MINIMAL,
    data_subject_rights_enabled=True,
    right_to_be_forgotten=False,  # Not implemented yet
    data_portability=False,
)

# Create GDPR policies
gdpr_strict_policy = create_gdpr_policy(gdpr_strict_config)
gdpr_standard_policy = create_gdpr_policy(gdpr_standard_config)
gdpr_minimal_policy = create_gdpr_policy(gdpr_minimal_config)

print("Created GDPR policies:")
print(f"  Strict: {len(gdpr_strict_policy.rules)} rules")
print(f"  Standard: {len(gdpr_standard_policy.rules)} rules")
print(f"  Minimal: {len(gdpr_minimal_policy.rules)} rules")

# %%
print("\n" + "🏥 HIPAA Compliance Configuration:")


@dataclass
class HIPAAConfiguration:
    """HIPAA-specific configuration"""

    covered_entity_type: (
        str  # "healthcare_provider", "health_plan", "healthcare_clearinghouse"
    )
    business_associate: bool = False
    minimum_necessary_standard: bool = True
    administrative_safeguards: bool = True
    physical_safeguards: bool = True
    technical_safeguards: bool = True
    breach_notification_days: int = 60
    security_officer_contact: str = "security@healthcare.com"


def create_hipaa_policy(config: HIPAAConfiguration) -> Policy:
    """Create a HIPAA-compliant policy"""

    # HIPAA requires protection of all PHI (Protected Health Information)
    hipaa_rules = [
        Rule(
            match="medical_record",
            action="tokenize",
            override_confidence=0.95,
        ),
        Rule(
            match="ssn",
            action="hash",
            override_confidence=0.95,
        ),
        Rule(
            match="person",
            action="tokenize",
            override_confidence=0.9,
        ),
        Rule(
            match="email",
            action="hash",
            override_confidence=0.85,
        ),
        Rule(
            match="phone",
            action="mask",
            override_confidence=0.85,
        ),
        Rule(
            match="ip",
            action="hash",
            override_confidence=0.8,
        ),
    ]

    # Additional rules for business associates
    if config.business_associate:
        ba_rules = [
            Rule(
                match="any",
                action="redact",
                override_confidence=0.5,
            )
        ]
        hipaa_rules.extend(ba_rules)

    policy = Policy(
        name=f"hipaa_policy_{config.covered_entity_type}",
        description=f"HIPAA compliance policy for {config.covered_entity_type}",
        rules=hipaa_rules,
        default_action="mask",
    )

    return policy


# Create HIPAA configurations
hipaa_provider_config = HIPAAConfiguration(
    covered_entity_type="healthcare_provider", business_associate=False
)

hipaa_ba_config = HIPAAConfiguration(
    covered_entity_type="business_associate",
    business_associate=True,
    breach_notification_days=30,  # Stricter for BA
)

# Create HIPAA policies
hipaa_provider_policy = create_hipaa_policy(hipaa_provider_config)
hipaa_ba_policy = create_hipaa_policy(hipaa_ba_config)

print("Created HIPAA policies:")
print(f"  Healthcare Provider: {len(hipaa_provider_policy.rules)} rules")
print(f"  Business Associate: {len(hipaa_ba_policy.rules)} rules")

# %%
print("\n" + "CCPA Compliance Configuration:")


@dataclass
class CCPAConfiguration:
    """CCPA-specific configuration"""

    business_threshold_met: bool = (
        True  # Annual revenue > $25M or processes >50K consumers
    )
    sale_of_personal_info: bool = False
    right_to_know: bool = True
    right_to_delete: bool = True
    right_to_opt_out: bool = True
    non_discrimination: bool = True
    privacy_officer_contact: str = "privacy@company.com"
    consumer_request_response_days: int = 45


def create_ccpa_policy(config: CCPAConfiguration) -> Policy:
    """Create a CCPA-compliant policy"""

    ccpa_rules = [
        Rule(
            match="person",
            action="tokenize" if config.sale_of_personal_info else "mask",
            override_confidence=0.85,
        ),
        Rule(
            match="email",
            action="hash",
            override_confidence=0.8,
        ),
        Rule(
            match="phone",
            action="mask",
            override_confidence=0.8,
        ),
        Rule(
            match="ip",
            action="hash",
            override_confidence=0.7,
        ),
    ]

    # Additional protections if business sells personal information
    if config.sale_of_personal_info:
        sale_rules = [
            Rule(
                match="any",
                action="redact",
                override_confidence=0.5,
            )
        ]
        ccpa_rules.extend(sale_rules)

    policy = Policy(
        name="ccpa_policy",
        description="CCPA compliance policy for California consumer privacy",
        rules=ccpa_rules,
        default_action="mask",
    )

    return policy


# Create CCPA configurations
ccpa_standard_config = CCPAConfiguration()
ccpa_sale_config = CCPAConfiguration(
    sale_of_personal_info=True,
    consumer_request_response_days=30,  # Faster response for businesses that sell data
)

# Create CCPA policies
ccpa_standard_policy = create_ccpa_policy(ccpa_standard_config)
ccpa_sale_policy = create_ccpa_policy(ccpa_sale_config)

print("Created CCPA policies:")
print(f"  Standard: {len(ccpa_standard_policy.rules)} rules")
print(f"  With Data Sales: {len(ccpa_sale_policy.rules)} rules")

# %%
print("\n" + "📊 Compliance Testing and Validation:")

# Create test data with various PII types
compliance_test_data = pd.DataFrame(
    {
        "patient_id": ["P001", "P002", "P003", "P004", "P005"],
        "patient_name": [
            "John Doe",
            "Jane Smith",
            "Bob Johnson",
            "Alice Brown",
            "Charlie Wilson",
        ],
        "email": [
            "john.doe@email.com",
            "jane.smith@email.com",
            "bob.j@email.com",
            "alice.b@email.com",
            "charlie.w@email.com",
        ],
        "phone": [
            "555-123-4567",
            "555-987-6543",
            "555-555-1234",
            "555-444-5555",
            "555-777-8888",
        ],
        "ssn": [
            "123-45-6789",
            "987-65-4321",
            "456-78-9012",
            "321-54-9876",
            "654-32-1098",
        ],
        "medical_record": ["MR123456", "MR789012", "MR345678", "MR901234", "MR567890"],
        "ip_address": [
            "192.168.1.100",
            "10.0.0.50",
            "172.16.0.25",
            "192.168.2.200",
            "10.1.1.75",
        ],
        "diagnosis": [
            "Hypertension",
            "Diabetes Type 2",
            "Asthma",
            "Arthritis",
            "Migraine",
        ],
        "treatment_date": [
            "2024-01-15",
            "2024-01-16",
            "2024-01-17",
            "2024-01-18",
            "2024-01-19",
        ],
    }
)


def test_compliance_policy(
    policy: Policy, test_data: pd.DataFrame, framework_name: str
):
    """Test a compliance policy against test data"""
    client = NoPIIClient(policy=policy)

    print(f"\nTesting {framework_name} policy:")
    print(f"  Policy: {policy.name}")
    print(f"  Rules: {len(policy.rules)}")

    # Apply policy to test data
    transformed_data, audit = client.transform_dataframe(
        test_data, dataset_name=f"{framework_name.lower()}_test"
    )

    # Analyze results
    findings_by_type = {}
    for finding in audit.scan_result.findings:
        detector_type = finding.type
        findings_by_type[detector_type] = findings_by_type.get(detector_type, 0) + 1

    print(f"  Coverage: {audit.coverage_score:.1%}")
    print(f"  Total findings: {len(audit.scan_result.findings)}")
    print(f"  Findings by type: {dict(findings_by_type)}")

    # Check compliance-specific requirements
    if "GDPR" in framework_name:
        print("  Framework: GDPR")
        print("  Breach notification: 72 hours (GDPR requirement)")
    elif "HIPAA" in framework_name:
        print("  Framework: HIPAA")
        print("  Breach notification: 60 days (HIPAA requirement)")
    elif "CCPA" in framework_name:
        print("  Framework: CCPA")
        print("  Consumer request response: 45 days (CCPA requirement)")

    return transformed_data, audit


# Test all compliance policies
gdpr_strict_results = test_compliance_policy(
    gdpr_strict_policy, compliance_test_data, "GDPR Strict"
)
gdpr_standard_results = test_compliance_policy(
    gdpr_standard_policy, compliance_test_data, "GDPR Standard"
)
hipaa_provider_results = test_compliance_policy(
    hipaa_provider_policy, compliance_test_data, "HIPAA Provider"
)
hipaa_ba_results = test_compliance_policy(
    hipaa_ba_policy, compliance_test_data, "HIPAA Business Associate"
)
ccpa_standard_results = test_compliance_policy(
    ccpa_standard_policy, compliance_test_data, "CCPA Standard"
)

# %%
print("\n" + "Compliance Audit Reporting:")


class ComplianceAuditReporter:
    """Generate comprehensive compliance audit reports"""

    def __init__(self):
        self.audit_results = {}

    def add_audit_result(
        self,
        framework: str,
        policy_name: str,
        audit_data: Any,
        transformed_data: pd.DataFrame,
    ):
        """Add audit result for a compliance framework"""
        self.audit_results[f"{framework}_{policy_name}"] = {
            "framework": framework,
            "policy_name": policy_name,
            "audit": audit_data,
            "transformed_data": transformed_data,
            "timestamp": datetime.now(),
        }

    def generate_compliance_summary(self) -> Dict[str, Any]:
        """Generate a summary of compliance across all frameworks"""
        summary = {
            "total_frameworks_tested": len(
                set(result["framework"] for result in self.audit_results.values())
            ),
            "total_policies_tested": len(self.audit_results),
            "overall_coverage": 0,
            "framework_performance": {},
            "risk_assessment": "LOW",
            "recommendations": [],
        }

        # Calculate overall metrics
        total_coverage = 0
        framework_stats = {}

        for key, result in self.audit_results.items():
            framework = result["framework"]
            coverage = result["audit"].coverage_score
            findings_count = len(result["audit"].scan_result.findings)

            if framework not in framework_stats:
                framework_stats[framework] = {
                    "policies": 0,
                    "total_coverage": 0,
                    "total_findings": 0,
                    "avg_coverage": 0,
                }

            framework_stats[framework]["policies"] += 1
            framework_stats[framework]["total_coverage"] += coverage
            framework_stats[framework]["total_findings"] += findings_count
            total_coverage += coverage

        # Calculate averages
        summary["overall_coverage"] = (
            total_coverage / len(self.audit_results) if self.audit_results else 0
        )

        for framework, stats in framework_stats.items():
            stats["avg_coverage"] = stats["total_coverage"] / stats["policies"]
            summary["framework_performance"][framework] = stats

        # Risk assessment
        if summary["overall_coverage"] >= 0.95:
            summary["risk_assessment"] = "LOW"
        elif summary["overall_coverage"] >= 0.85:
            summary["risk_assessment"] = "MEDIUM"
        else:
            summary["risk_assessment"] = "HIGH"

        # Generate recommendations
        if summary["overall_coverage"] < 0.9:
            summary["recommendations"].append(
                "Increase PII detection coverage to meet compliance requirements"
            )

        if any(stats["avg_coverage"] < 0.8 for stats in framework_stats.values()):
            summary["recommendations"].append(
                "Review and strengthen policies for underperforming frameworks"
            )

        summary["recommendations"].append(
            "Conduct regular compliance audits and policy reviews"
        )
        summary["recommendations"].append(
            "Implement automated monitoring for continuous compliance"
        )

        return summary

    def generate_detailed_report(self) -> str:
        """Generate a detailed compliance audit report"""
        summary = self.generate_compliance_summary()

        report = f"""
COMPLIANCE AUDIT REPORT
======================
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

EXECUTIVE SUMMARY
-----------------
Overall Risk Level: {summary["risk_assessment"]}
Overall Coverage: {summary["overall_coverage"]:.1%}
Frameworks Tested: {summary["total_frameworks_tested"]}
Policies Tested: {summary["total_policies_tested"]}

FRAMEWORK PERFORMANCE
--------------------
"""

        for framework, stats in summary["framework_performance"].items():
            report += f"""
{framework}:
  Policies Tested: {stats["policies"]}
  Average Coverage: {stats["avg_coverage"]:.1%}
  Total Findings: {stats["total_findings"]}
"""

        report += """
DETAILED FINDINGS
----------------
"""

        for key, result in self.audit_results.items():
            audit = result["audit"]
            report += f"""
{result["framework"]} - {result["policy_name"]}:
  Coverage: {audit.coverage_score:.1%}
  Findings: {len(audit.scan_result.findings)}
  Timestamp: {result["timestamp"].strftime("%Y-%m-%d %H:%M:%S")}
"""

        report += """
RECOMMENDATIONS
--------------
"""
        for i, rec in enumerate(summary["recommendations"], 1):
            report += f"{i}. {rec}\n"

        report += """
COMPLIANCE CHECKLIST
-------------------
□ Data inventory and mapping completed
□ Privacy policies updated and published
□ Staff training on data protection completed
□ Technical safeguards implemented and tested
□ Incident response procedures documented
□ Regular compliance audits scheduled
□ Data subject rights procedures established
□ Vendor agreements include compliance requirements
"""

        return report


# Create compliance audit reporter
audit_reporter = ComplianceAuditReporter()

# Add all audit results
audit_reporter.add_audit_result(
    "GDPR", "strict", gdpr_strict_results[1], gdpr_strict_results[0]
)
audit_reporter.add_audit_result(
    "GDPR", "standard", gdpr_standard_results[1], gdpr_standard_results[0]
)
audit_reporter.add_audit_result(
    "HIPAA", "provider", hipaa_provider_results[1], hipaa_provider_results[0]
)
audit_reporter.add_audit_result(
    "HIPAA", "business_associate", hipaa_ba_results[1], hipaa_ba_results[0]
)
audit_reporter.add_audit_result(
    "CCPA", "standard", ccpa_standard_results[1], ccpa_standard_results[0]
)

# Generate compliance summary
compliance_summary = audit_reporter.generate_compliance_summary()
print("\nCompliance Summary:")
print(f"  Overall Risk: {compliance_summary['risk_assessment']}")
print(f"  Overall Coverage: {compliance_summary['overall_coverage']:.1%}")
print(f"  Frameworks: {list(compliance_summary['framework_performance'].keys())}")

# Generate detailed report
detailed_report = audit_reporter.generate_detailed_report()
print(f"\nDetailed compliance report generated ({len(detailed_report)} characters)")

# %%
print("\n" + "🚨 Breach Detection and Notification:")


class BreachDetectionSystem:
    """Detect potential data breaches and generate notifications"""

    def __init__(self):
        self.breach_thresholds = {
            "high_volume_access": 1000,  # Records accessed in short time
            "unusual_access_pattern": 0.8,  # Confidence threshold
            "failed_protection_rate": 0.1,  # 10% failure rate triggers alert
            "sensitive_data_exposure": 0.05,  # 5% sensitive data exposure
        }
        self.detected_breaches = []

    def analyze_processing_session(
        self, audit_results: List[Any], session_name: str
    ) -> Dict[str, Any]:
        """Analyze a processing session for potential breaches"""

        total_records = sum(len(audit.scan_result.findings) for audit in audit_results)
        total_coverage = sum(audit.coverage_score for audit in audit_results) / len(
            audit_results
        )

        # Calculate risk indicators
        risk_indicators = {
            "high_volume_processing": total_records
            > self.breach_thresholds["high_volume_access"],
            "low_protection_coverage": total_coverage
            < (1 - self.breach_thresholds["failed_protection_rate"]),
            "sensitive_data_detected": any(
                finding.confidence > 0.9
                for audit in audit_results
                for finding in audit.scan_result.findings
            ),
            "unusual_patterns": False,  # Placeholder for pattern analysis
        }

        # Determine breach likelihood
        risk_score = sum(risk_indicators.values()) / len(risk_indicators)

        breach_analysis = {
            "session_name": session_name,
            "timestamp": datetime.now(),
            "total_records_processed": total_records,
            "average_coverage": total_coverage,
            "risk_indicators": risk_indicators,
            "risk_score": risk_score,
            "breach_likelihood": "HIGH"
            if risk_score > 0.6
            else "MEDIUM"
            if risk_score > 0.3
            else "LOW",
            "requires_notification": risk_score > 0.5,
        }

        if breach_analysis["requires_notification"]:
            self.detected_breaches.append(breach_analysis)

        return breach_analysis

    def generate_breach_notification(
        self, breach_analysis: Dict[str, Any], compliance_framework: str
    ) -> str:
        """Generate a breach notification based on compliance framework"""

        # Framework-specific notification requirements
        notification_timeframes = {
            "GDPR": "72 hours to supervisory authority, without undue delay to data subjects",
            "HIPAA": "60 days to HHS, without unreasonable delay to individuals",
            "CCPA": "Without unreasonable delay, considering legitimate needs of law enforcement",
        }

        notification = f"""
POTENTIAL DATA BREACH NOTIFICATION
=================================

INCIDENT DETAILS
---------------
Session: {breach_analysis["session_name"]}
Detection Time: {breach_analysis["timestamp"].strftime("%Y-%m-%d %H:%M:%S")}
Risk Level: {breach_analysis["breach_likelihood"]}
Risk Score: {breach_analysis["risk_score"]:.2f}

SCOPE OF INCIDENT
----------------
Records Processed: {breach_analysis["total_records_processed"]:,}
Protection Coverage: {breach_analysis["average_coverage"]:.1%}

RISK INDICATORS
--------------
"""

        for indicator, detected in breach_analysis["risk_indicators"].items():
            status = "DETECTED" if detected else "NOT DETECTED"
            notification += f"- {indicator.replace('_', ' ').title()}: {status}\n"

        notification += f"""
COMPLIANCE REQUIREMENTS ({compliance_framework})
{"-" * (25 + len(compliance_framework))}
Notification Timeframe: {notification_timeframes.get(compliance_framework, "As required by applicable law")}

IMMEDIATE ACTIONS REQUIRED
-------------------------
1. Contain the incident and assess ongoing risk
2. Document all relevant details and evidence
3. Notify appropriate stakeholders per compliance requirements
4. Implement additional safeguards to prevent recurrence
5. Prepare detailed incident report for regulators
6. Consider notification to affected individuals if required

CONTACT INFORMATION
------------------
Security Team: security@company.com
Legal Team: legal@company.com
Compliance Officer: compliance@company.com
"""

        return notification


# Test breach detection
breach_detector = BreachDetectionSystem()

# Analyze our compliance test results
all_audit_results = [
    gdpr_strict_results[1],
    gdpr_standard_results[1],
    hipaa_provider_results[1],
    hipaa_ba_results[1],
    ccpa_standard_results[1],
]

breach_analysis = breach_detector.analyze_processing_session(
    all_audit_results, "compliance_testing_session"
)

print("Breach Analysis Results:")
print(f"  Risk Level: {breach_analysis['breach_likelihood']}")
print(f"  Risk Score: {breach_analysis['risk_score']:.2f}")
print(f"  Requires Notification: {breach_analysis['requires_notification']}")

if breach_analysis["requires_notification"]:
    gdpr_notification = breach_detector.generate_breach_notification(
        breach_analysis, "GDPR"
    )
    print(f"\nGDPR breach notification generated ({len(gdpr_notification)} characters)")

# %%
print("\n" + "📈 Governance Dashboard and Metrics:")


class ComplianceGovernanceDashboard:
    """Comprehensive governance dashboard for compliance monitoring"""

    def __init__(self):
        self.metrics = {
            "policy_compliance_scores": {},
            "framework_coverage": {},
            "risk_trends": [],
            "audit_history": [],
            "training_completion": {},
            "incident_count": 0,
            "last_assessment_date": None,
        }

    def update_compliance_metrics(self, audit_reporter: ComplianceAuditReporter):
        """Update compliance metrics from audit results"""
        summary = audit_reporter.generate_compliance_summary()

        self.metrics["policy_compliance_scores"] = {
            framework: stats["avg_coverage"]
            for framework, stats in summary["framework_performance"].items()
        }

        self.metrics["framework_coverage"] = summary["framework_performance"]
        self.metrics["last_assessment_date"] = datetime.now()

        # Add to risk trends
        overall_risk_score = (
            1 - summary["overall_coverage"]
        )  # Higher coverage = lower risk
        self.metrics["risk_trends"].append(
            {
                "date": datetime.now(),
                "risk_score": overall_risk_score,
                "overall_coverage": summary["overall_coverage"],
            }
        )

    def update_incident_metrics(self, breach_detector: BreachDetectionSystem):
        """Update incident metrics from breach detection"""
        self.metrics["incident_count"] = len(breach_detector.detected_breaches)

        for breach in breach_detector.detected_breaches:
            self.metrics["audit_history"].append(
                {
                    "date": breach["timestamp"],
                    "type": "potential_breach",
                    "risk_level": breach["breach_likelihood"],
                    "session": breach["session_name"],
                }
            )

    def generate_governance_report(self) -> str:
        """Generate comprehensive governance report"""

        report = f"""
COMPLIANCE GOVERNANCE DASHBOARD
==============================
Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Last Assessment: {self.metrics["last_assessment_date"].strftime("%Y-%m-%d") if self.metrics["last_assessment_date"] else "Never"}

KEY PERFORMANCE INDICATORS
--------------------------
"""

        # Policy compliance scores
        if self.metrics["policy_compliance_scores"]:
            report += "Policy Compliance Scores:\n"
            for framework, score in self.metrics["policy_compliance_scores"].items():
                status = "✓" if score >= 0.9 else "⚠" if score >= 0.8 else "✗"
                report += f"  {status} {framework}: {score:.1%}\n"

        # Risk assessment
        if self.metrics["risk_trends"]:
            latest_risk = self.metrics["risk_trends"][-1]
            risk_level = (
                "LOW"
                if latest_risk["risk_score"] < 0.1
                else "MEDIUM"
                if latest_risk["risk_score"] < 0.2
                else "HIGH"
            )
            report += f"\nCurrent Risk Level: {risk_level}\n"
            report += f"Overall Coverage: {latest_risk['overall_coverage']:.1%}\n"

        # Incident summary
        report += "\nIncident Summary:\n"
        report += f"  Total Incidents: {self.metrics['incident_count']}\n"

        if self.metrics["audit_history"]:
            recent_incidents = [
                inc
                for inc in self.metrics["audit_history"]
                if inc["date"] > datetime.now() - timedelta(days=30)
            ]
            report += f"  Recent Incidents (30 days): {len(recent_incidents)}\n"

        # Framework performance
        report += "\nFramework Performance:\n"
        for framework, stats in self.metrics["framework_coverage"].items():
            report += f"  {framework}:\n"
            report += f"    Policies: {stats['policies']}\n"
            report += f"    Coverage: {stats['avg_coverage']:.1%}\n"
            report += f"    Findings: {stats['total_findings']}\n"

        # Governance recommendations
        report += """
GOVERNANCE RECOMMENDATIONS
--------------------------
1. Conduct quarterly compliance assessments
2. Implement continuous monitoring for all frameworks
3. Regular staff training on data protection requirements
4. Maintain incident response procedures and test regularly
5. Review and update policies annually or when regulations change
6. Establish clear data governance roles and responsibilities
7. Implement automated compliance monitoring tools
8. Regular third-party compliance audits

COMPLIANCE CALENDAR
------------------
- Monthly: Review incident reports and metrics
- Quarterly: Comprehensive compliance assessment
- Semi-annually: Policy review and updates
- Annually: Full compliance audit and training refresh
"""

        return report


# Create governance dashboard
governance_dashboard = ComplianceGovernanceDashboard()

# Update with our compliance and incident data
governance_dashboard.update_compliance_metrics(audit_reporter)
governance_dashboard.update_incident_metrics(breach_detector)

# Generate governance report
governance_report = governance_dashboard.generate_governance_report()
print("Governance report generated:")
print(
    governance_report[:500] + "..."
    if len(governance_report) > 500
    else governance_report
)

# %%
print("\n" + "💾 Saving Compliance Artifacts:")

# Create compliance output directory
script_dir = Path(__file__).parent
compliance_dir = script_dir / "outputs/compliance_outputs"
compliance_dir.mkdir(parents=True, exist_ok=True)

# Save policies
policies_dir = compliance_dir / "policies"
policies_dir.mkdir(exist_ok=True)

policy_exports = {
    "gdpr_strict_policy.json": gdpr_strict_policy,
    "gdpr_standard_policy.json": gdpr_standard_policy,
    "hipaa_provider_policy.json": hipaa_provider_policy,
    "hipaa_ba_policy.json": hipaa_ba_policy,
    "ccpa_standard_policy.json": ccpa_standard_policy,
}

for filename, policy in policy_exports.items():
    policy_file = policies_dir / filename
    # Note: In a real implementation, you'd use policy.to_json() or similar
    policy_data = {
        "name": policy.name,
        "description": policy.description,
        "rules_count": len(policy.rules),
        "created": datetime.now().isoformat(),
    }

    with open(policy_file, "w") as f:
        json.dump(policy_data, f, indent=2)

    print(f"  Saved: {policy_file}")

# Save reports
reports_dir = compliance_dir / "reports"
reports_dir.mkdir(exist_ok=True)

# Save detailed compliance report
compliance_report_file = (
    reports_dir / f"compliance_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
)
with open(compliance_report_file, "w") as f:
    f.write(detailed_report)
print(f"  Saved: {compliance_report_file}")

# Save governance report
governance_report_file = (
    reports_dir / f"governance_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
)
with open(governance_report_file, "w") as f:
    f.write(governance_report)
print(f"  Saved: {governance_report_file}")

# Save breach notification if any
if breach_detector.detected_breaches:
    breach_notification_file = (
        reports_dir
        / f"breach_notification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    with open(breach_notification_file, "w") as f:
        f.write(gdpr_notification)
    print(f"  Saved: {breach_notification_file}")

print(f"\nCompliance artifacts saved to: {compliance_dir}")

# %%
print("\n" + "🎯 Key Takeaways:")
print("=" * 50)

print("""
Compliance and Governance Best Practices:

1. Framework-Specific Policies:
   • GDPR: Focus on data subject rights and lawful basis
   • HIPAA: Protect all PHI with appropriate safeguards
   • CCPA: Implement consumer rights and opt-out mechanisms

2. Risk-Based Approach:
   • Assess data sensitivity and processing context
   • Implement controls proportionate to risk level
   • Regular monitoring and assessment

3. Automated Compliance:
   • Use policy-driven PII protection
   • Implement continuous monitoring
   • Generate automated compliance reports

4. Incident Response:
   • Detect potential breaches early
   • Follow framework-specific notification requirements
   • Maintain detailed incident documentation

5. Governance Framework:
   • Establish clear roles and responsibilities
   • Regular policy reviews and updates
   • Comprehensive audit trails and reporting

6. Continuous Improvement:
   • Regular compliance assessments
   • Staff training and awareness
   • Technology updates and enhancements
""")

print("\n" + "📚 Next Steps:")
print("- Review and customize policies for your specific use case")
print("- Implement automated monitoring and alerting")
print("- Establish regular compliance assessment schedules")
print("- Train staff on data protection requirements")
print("- Consider third-party compliance audits")
print("- Stay updated on regulatory changes and requirements")
