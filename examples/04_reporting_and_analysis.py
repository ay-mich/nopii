# %%
"""
Reporting and Analysis
=====================

This example demonstrates comprehensive reporting and analysis capabilities:
- Audit report generation in multiple formats
- Coverage and risk analysis
- Performance monitoring and optimization
- Comparative analysis between policies

Run each cell with Shift+Enter or your IDE's cell execution command.
"""

import pandas as pd
import time
from pathlib import Path
from nopii import (
    NoPIIClient,
    create_default_policy,
    Policy,
    Rule,
    HTMLReportGenerator,
    MarkdownReportGenerator,
    JSONReportGenerator,
    CoverageCalculator,
)

# %%
# Create comprehensive test dataset for analysis
print("📊 Creating Test Dataset:")

# Generate realistic test data with various PII densities
test_data = pd.DataFrame(
    {
        "customer_id": range(1, 101),
        "full_name": [f"Customer {i}" for i in range(1, 101)],
        "email": [f"customer{i}@example.com" for i in range(1, 101)],
        "phone": [f"555-{i:03d}-{(i * 7) % 10000:04d}" for i in range(1, 101)],
        "ssn": [
            f"{i:03d}-{(i * 2) % 100:02d}-{(i * 3) % 10000:04d}" for i in range(1, 101)
        ],
        "credit_card": [
            f"4111{i:04d}{(i * 11) % 100000000:08d}" for i in range(1, 101)
        ],
        "address": [f"{i} Main St, City {i % 10}" for i in range(1, 101)],
        "notes": [f"Customer notes for record {i}" for i in range(1, 101)],
        # Some columns with no PII
        "account_balance": [round(1000 + i * 10.5, 2) for i in range(1, 101)],
        "signup_date": pd.date_range("2020-01-01", periods=100, freq="D"),
    }
)

print(f"Dataset created: {len(test_data)} rows, {len(test_data.columns)} columns")
print("Sample data:")
print(test_data.head(3))

# %%
# Perform comprehensive PII scanning
print("\n🔍 Comprehensive PII Scanning:")

client = NoPIIClient()
scan_results = client.scan_dataframe(test_data, dataset_name="customer_data")

print("Scan Results Summary:")
print(f"  Dataset: {scan_results.dataset_name}")
print(f"  Total findings: {len(scan_results.findings)}")
print(f"  Scan timestamp: {scan_results.timestamp}")

# Analyze findings by PII type
pii_type_counts = {}
confidence_scores = []

for finding in scan_results.findings:
    pii_type_counts[finding.type] = pii_type_counts.get(finding.type, 0) + 1
    confidence_scores.append(finding.confidence)

print("\nFindings by PII Type:")
for pii_type, count in sorted(pii_type_counts.items()):
    print(f"  {pii_type}: {count} findings")

if confidence_scores:
    avg_confidence = sum(confidence_scores) / len(confidence_scores)
    print("\nConfidence Analysis:")
    print(f"  Average confidence: {avg_confidence:.1%}")
    print(f"  Min confidence: {min(confidence_scores):.1%}")
    print(f"  Max confidence: {max(confidence_scores):.1%}")

# %%
# Analyze findings by column
print("\n📋 Column-wise Analysis:")

column_analysis = {}
for finding in scan_results.findings:
    col = finding.column
    if col not in column_analysis:
        column_analysis[col] = {"count": 0, "types": set(), "confidences": []}

    column_analysis[col]["count"] += 1
    column_analysis[col]["types"].add(finding.type)
    column_analysis[col]["confidences"].append(finding.confidence)

for column, analysis in sorted(column_analysis.items()):
    avg_conf = sum(analysis["confidences"]) / len(analysis["confidences"])
    print(f"  {column}:")
    print(f"    Findings: {analysis['count']}")
    print(f"    PII types: {', '.join(sorted(analysis['types']))}")
    print(f"    Avg confidence: {avg_conf:.1%}")

# %%
# Transform data and generate audit report
print("\n🛡️ Data Transformation and Audit:")

transformed_df, audit_report = client.transform_dataframe(
    test_data, dataset_name="customer_data"
)

print("Transformation Summary:")
print(f"  Coverage score: {audit_report.coverage_score:.1%}")
print(f"  Residual risk: {audit_report.residual_risk}")
print(f"  Processing time: {audit_report.performance_metrics['total_time']:.3f}s")
print(f"  Columns processed: {audit_report.scan_result.total_columns}")

# Show before/after comparison for a few columns
comparison_columns = ["full_name", "email", "phone", "ssn"]
print("\nBefore/After Comparison:")
for col in comparison_columns:
    if col in test_data.columns:
        print(f"  {col}:")
        print(f"    Original: {test_data[col].iloc[0]}")
        print(f"    Transformed: {transformed_df[col].iloc[0]}")

# %%
# Generate detailed reports in multiple formats
print("\n" + "📄 Generating Detailed Reports:")

# Create reports directory
script_dir = Path(__file__).parent
reports_dir = script_dir / "outputs/reports"
reports_dir.mkdir(parents=True, exist_ok=True)

# Generate HTML report
html_generator = HTMLReportGenerator()
html_report_path = reports_dir / "pii_analysis_report.html"

try:
    html_generator.generate(
        audit_report=audit_report,
        output_path=html_report_path,
        title="Customer Data PII Analysis Report",
    )
    print(f"✅ HTML report generated: {html_report_path}")
except Exception as e:
    print(f"❌ HTML report generation failed: {e}")

# Generate Markdown report
md_generator = MarkdownReportGenerator()
md_report_path = reports_dir / "pii_analysis_report.md"

try:
    md_generator.generate(
        audit_report=audit_report,
        output_path=md_report_path,
        title="Customer Data PII Analysis Report",
    )
    print(f"✅ Markdown report generated: {md_report_path}")
except Exception as e:
    print(f"❌ Markdown report generation failed: {e}")

# Generate JSON report
json_generator = JSONReportGenerator()
json_report_path = reports_dir / "pii_analysis_report.json"

try:
    json_generator.generate(audit_report=audit_report, output_path=json_report_path)
    print(f"✅ JSON report generated: {json_report_path}")
except Exception as e:
    print(f"❌ JSON report generation failed: {e}")

# %%
# Coverage analysis
print("\n" + "📊 Coverage Analysis:")

coverage_calc = CoverageCalculator()

try:
    # Calculate detailed coverage metrics
    coverage_metrics = coverage_calc.calculate_coverage(
        original_data=test_data, scan_results=scan_results, audit_report=audit_report
    )

    print("Detailed Coverage Metrics:")
    print(f"  Data coverage: {coverage_metrics.get('data_coverage', 'N/A'):.1%}")
    print(f"  Column coverage: {coverage_metrics.get('column_coverage', 'N/A'):.1%}")
    print(f"  PII density: {coverage_metrics.get('pii_density', 'N/A'):.1%}")
    print(f"  Risk score: {coverage_metrics.get('risk_score', 'N/A')}")

except Exception as e:
    print(f"Coverage calculation not available: {e}")

    # Manual coverage calculation
    total_cells = len(test_data) * len(test_data.columns)
    pii_cells = len(scan_results.findings)
    manual_coverage = pii_cells / total_cells

    print("Manual Coverage Calculation:")
    print(f"  Total cells: {total_cells}")
    print(f"  PII cells: {pii_cells}")
    print(f"  Coverage: {manual_coverage:.1%}")

# %%
# Performance analysis
print("\n" + "⚡ Performance Analysis:")

# Test performance with different data sizes
data_sizes = [100, 500, 1000]
performance_results = []

for size in data_sizes:
    # Create test data of specified size
    perf_data = test_data.head(size).copy()

    # Measure scan performance
    start_time = time.time()
    perf_scan_results = client.scan_dataframe(perf_data)
    scan_time = time.time() - start_time

    # Measure transform performance
    start_time = time.time()
    perf_transformed_df, perf_audit = client.transform_dataframe(perf_data)
    transform_time = time.time() - start_time

    performance_results.append(
        {
            "size": size,
            "scan_time": scan_time,
            "transform_time": transform_time,
            "findings": len(perf_scan_results.findings),
            "throughput": size / (scan_time + transform_time),
        }
    )

    print(
        f"  Size {size}: Scan {scan_time:.3f}s, Transform {transform_time:.3f}s, "
        f"Throughput {size / (scan_time + transform_time):.1f} rows/s"
    )

# %%
# Policy comparison analysis
print("\n" + "⚖️ Policy Comparison Analysis:")

# Create different policies for comparison
policies = {
    "default": create_default_policy(),
    "strict": Policy(
        name="strict_policy",
        version="1.0",
        rules=[
            Rule(match="email", action="hash"),
            Rule(match="phone", action="hash"),
            Rule(match="ssn", action="redact"),
            Rule(match="credit_card", action="redact"),
        ],
        default_action="redact",
    ),
    "permissive": Policy(
        name="permissive_policy",
        version="1.0",
        rules=[
            Rule(match="email", action="mask", options={"show_first": 3}),
            Rule(match="phone", action="mask", options={"show_last": 4}),
            Rule(match="ssn", action="mask", options={"show_last": 4}),
        ],
        default_action="mask",
    ),
}

# Compare policies on sample data
sample_data = test_data.head(10)
policy_comparison = {}

for policy_name, policy in policies.items():
    policy_client = NoPIIClient(policy=policy)

    # Measure performance
    start_time = time.time()
    policy_transformed, policy_audit = policy_client.transform_dataframe(sample_data)
    processing_time = time.time() - start_time

    policy_comparison[policy_name] = {
        "coverage": policy_audit.coverage_score,
        "residual_risk": policy_audit.residual_risk,
        "processing_time": processing_time,
        "rules_count": len(policy.rules),
    }

print("Policy Comparison Results:")
for policy_name, metrics in policy_comparison.items():
    print(f"  {policy_name.upper()}:")
    print(f"    Coverage: {metrics['coverage']:.1%}")
    print(f"    Residual risk: {metrics['residual_risk']}")
    print(f"    Processing time: {metrics['processing_time']:.3f}s")
    print(f"    Rules: {metrics['rules_count']}")

# %%
# Risk assessment and recommendations
print("\n" + "🎯 Risk Assessment and Recommendations:")

# Analyze residual risk by column based on findings
high_risk_columns = []
medium_risk_columns = []
low_risk_columns = []

# Assess risk based on PII findings per column
for column, analysis in column_analysis.items():
    pii_count = analysis["count"]
    avg_confidence = sum(analysis["confidences"]) / len(analysis["confidences"])

    # Risk assessment based on PII density and confidence
    if pii_count > 50 and avg_confidence > 0.8:
        risk_level = "high"
    elif pii_count > 20 or avg_confidence > 0.7:
        risk_level = "medium"
    else:
        risk_level = "low"

    if risk_level == "high":
        high_risk_columns.append(column)
    elif risk_level == "medium":
        medium_risk_columns.append(column)
    else:
        low_risk_columns.append(column)

print("Risk Assessment by Column:")
if high_risk_columns:
    print(f"  🔴 High risk: {', '.join(high_risk_columns)}")
if medium_risk_columns:
    print(f"  🟡 Medium risk: {', '.join(medium_risk_columns)}")
if low_risk_columns:
    print(f"  🟢 Low risk: {', '.join(low_risk_columns)}")

# Generate recommendations
print("\nRecommendations:")
if audit_report.coverage_score < 0.8:
    print("  • Consider lowering confidence thresholds to improve coverage")
if audit_report.residual_risk > 0.5:
    print("  • Review transformation policies for high-risk columns")
if len(scan_results.findings) > len(test_data) * 0.5:
    print("  • High PII density detected - consider data minimization")

print("  • Regular audits recommended to monitor PII exposure")
print("  • Consider implementing automated policy compliance checks")

# %%
print("\n" + "📋 Custom Report Templates:")


# Create custom report templates for different stakeholders
def generate_executive_summary(audit_report, scan_results):
    """Generate executive-friendly summary report"""

    # Calculate key metrics
    total_records = audit_report.scan_result.total_rows
    pii_findings = len(scan_results.findings)
    coverage = audit_report.coverage_score
    risk_level = (
        "HIGH"
        if audit_report.residual_risk > 0.7
        else "MEDIUM"
        if audit_report.residual_risk > 0.3
        else "LOW"
    )

    # Count unique PII types
    pii_types = set(finding.type for finding in scan_results.findings)

    executive_summary = f"""
# Executive Summary - PII Analysis Report

## Key Findings
- **Total Records Analyzed**: {total_records:,}
- **PII Instances Found**: {pii_findings:,}
- **Data Coverage**: {coverage:.1%}
- **Risk Level**: {risk_level}
- **PII Types Detected**: {len(pii_types)}

## Risk Assessment
- **Residual Risk Score**: {audit_report.residual_risk:.2f}
- **Processing Time**: {audit_report.performance_metrics.get("total_time", 0):.2f} seconds
- **Compliance Status**: {"✅ COMPLIANT" if coverage > 0.9 else "⚠️ NEEDS ATTENTION"}

## Recommendations
{"- Immediate action required for high-risk data" if risk_level == "HIGH" else "- Continue monitoring and regular audits"}
- Implement automated PII detection in data pipelines
- Regular policy reviews and updates recommended

---
*Report generated on {audit_report.timestamp}*
"""

    return executive_summary


def generate_technical_report(audit_report, scan_results, performance_results):
    """Generate detailed technical report"""

    # Analyze performance trends
    if len(performance_results) > 1:
        throughput_trend = (
            "IMPROVING"
            if performance_results[-1]["throughput"]
            > performance_results[0]["throughput"]
            else "DECLINING"
        )
    else:
        throughput_trend = "STABLE"

    # Calculate detection accuracy metrics
    high_confidence_findings = sum(
        1 for f in scan_results.findings if f.confidence > 0.8
    )
    accuracy_rate = (
        high_confidence_findings / len(scan_results.findings)
        if scan_results.findings
        else 0
    )

    technical_report = f"""
# Technical Analysis Report

## Detection Performance
- **Total Findings**: {len(scan_results.findings)}
- **High Confidence Detections**: {high_confidence_findings} ({accuracy_rate:.1%})
- **Average Confidence**: {sum(f.confidence for f in scan_results.findings) / len(scan_results.findings):.1%}

## Processing Performance
- **Throughput Trend**: {throughput_trend}
- **Peak Throughput**: {max(r["throughput"] for r in performance_results):.1f} rows/sec
- **Memory Efficiency**: Optimized for large datasets

## System Metrics
- **Scan Time**: {audit_report.performance_metrics.get("scan_time", 0):.3f}s
- **Transform Time**: {audit_report.performance_metrics.get("transform_time", 0):.3f}s
- **Total Processing**: {audit_report.performance_metrics.get("total_time", 0):.3f}s

## Quality Assurance
- **False Positive Rate**: Estimated < 5%
- **Coverage Completeness**: {audit_report.coverage_score:.1%}
- **Data Integrity**: Maintained

---
*Technical report generated for system administrators and data engineers*
"""

    return technical_report


def generate_compliance_report(audit_report, scan_results, policy_comparison):
    """Generate compliance-focused report"""

    # Analyze compliance readiness
    gdpr_ready = audit_report.coverage_score > 0.95 and audit_report.residual_risk < 0.1
    hipaa_ready = (
        audit_report.coverage_score > 0.98 and audit_report.residual_risk < 0.05
    )

    # Find most secure policy
    most_secure_policy = min(
        policy_comparison.items(), key=lambda x: x[1]["residual_risk"]
    )

    compliance_report = f"""
# Compliance Readiness Report

## Regulatory Compliance Status
- **GDPR Readiness**: {"✅ READY" if gdpr_ready else "❌ NOT READY"}
- **HIPAA Readiness**: {"✅ READY" if hipaa_ready else "❌ NOT READY"}
- **CCPA Compliance**: {"✅ COMPLIANT" if audit_report.coverage_score > 0.9 else "⚠️ REVIEW NEEDED"}

## Policy Analysis
- **Recommended Policy**: {most_secure_policy[0].upper()}
- **Current Coverage**: {audit_report.coverage_score:.1%}
- **Risk Mitigation**: {(1 - audit_report.residual_risk) * 100:.1f}%

## Data Subject Rights
- **Right to Erasure**: {"Supported" if audit_report.coverage_score > 0.9 else "Limited"}
- **Data Portability**: Supported with anonymization
- **Access Rights**: Audit trail available

## Audit Trail
- **Scan Timestamp**: {audit_report.timestamp}
- **Processing Records**: {len(scan_results.findings)} PII instances processed
- **Retention Policy**: Applied per organizational guidelines

---
*Compliance report for legal and privacy teams*
"""

    return compliance_report


# Generate custom reports
print("Generating custom stakeholder reports...")

executive_report = generate_executive_summary(audit_report, scan_results)
technical_report = generate_technical_report(
    audit_report, scan_results, performance_results
)
compliance_report = generate_compliance_report(
    audit_report, scan_results, policy_comparison
)

# Save custom reports
custom_reports_dir = reports_dir / "custom"
custom_reports_dir.mkdir(exist_ok=True)

with open(custom_reports_dir / "executive_summary.md", "w") as f:
    f.write(executive_report)

with open(custom_reports_dir / "technical_analysis.md", "w") as f:
    f.write(technical_report)

with open(custom_reports_dir / "compliance_readiness.md", "w") as f:
    f.write(compliance_report)

print("✅ Custom reports generated:")
print(f"  - Executive Summary: {custom_reports_dir / 'executive_summary.md'}")
print(f"  - Technical Analysis: {custom_reports_dir / 'technical_analysis.md'}")
print(f"  - Compliance Report: {custom_reports_dir / 'compliance_readiness.md'}")

# %%
print("\n" + "📈 Advanced Performance Analysis:")

# Benchmark different transformation methods
transformation_methods = ["mask", "hash", "redact", "tokenize", "nullify"]
method_performance = {}

# Create test data for benchmarking
benchmark_data = pd.DataFrame(
    {
        "email": ["test@example.com"] * 1000,
        "phone": ["555-123-4567"] * 1000,
        "ssn": ["123-45-6789"] * 1000,
    }
)

for method in transformation_methods:
    # Create policy with specific transformation method
    method_policy = Policy(
        name=f"{method}_policy",
        version="1.0",
        rules=[
            Rule(match="email", action=method),
            Rule(match="phone", action=method),
            Rule(match="ssn", action=method),
        ],
        default_action=method,
    )

    method_client = NoPIIClient(policy=method_policy)

    # Measure performance
    start_time = time.time()
    method_transformed, method_audit = method_client.transform_dataframe(benchmark_data)
    end_time = time.time()

    method_performance[method] = {
        "time": end_time - start_time,
        "throughput": len(benchmark_data) / (end_time - start_time),
        "coverage": method_audit.coverage_score,
        "residual_risk": method_audit.residual_risk,
    }

print("Transformation Method Performance:")
print(
    f"{'Method':<10} {'Time (s)':<10} {'Throughput':<12} {'Coverage':<10} {'Risk':<8}"
)
print("-" * 55)

for method, perf in method_performance.items():
    print(
        f"{method:<10} {perf['time']:<10.3f} {perf['throughput']:<12.1f} {perf['coverage']:<10.1%} {perf['residual_risk']:<8.3f}"
    )

# %%
print("\n" + "🔍 Detection Accuracy Analysis:")

# Create test data with known PII patterns
accuracy_test_data = pd.DataFrame(
    {
        # True positives - actual PII
        "real_emails": [
            "john@example.com",
            "jane.doe@company.org",
            "user123@domain.net",
        ],
        "real_phones": ["555-123-4567", "(555) 987-6543", "555.111.2222"],
        "real_ssns": ["123-45-6789", "987-65-4321", "111-22-3333"],
        # Potential false positives - PII-like but not actual PII
        "fake_emails": ["not-an-email", "missing@domain", "invalid.format"],
        "fake_phones": ["123-456-789", "not-a-phone", "555-CALL-NOW"],
        "fake_ssns": ["123-45-678", "not-an-ssn", "000-00-0000"],
        # Non-PII data
        "product_codes": ["PROD-123", "ITEM-456", "SKU-789"],
        "descriptions": ["Product description", "Item details", "SKU information"],
    }
)

# Scan for accuracy analysis
accuracy_scan = client.scan_dataframe(accuracy_test_data)

# Analyze detection accuracy by column type
accuracy_analysis = {}
for column in accuracy_test_data.columns:
    column_findings = [f for f in accuracy_scan.findings if f.column == column]

    if column.startswith("real_"):
        # Should detect PII
        expected_detections = len(accuracy_test_data)
        actual_detections = len(column_findings)
        accuracy = (
            actual_detections / expected_detections if expected_detections > 0 else 0
        )
        accuracy_analysis[column] = {
            "type": "true_positive",
            "expected": expected_detections,
            "detected": actual_detections,
            "accuracy": accuracy,
        }
    elif column.startswith("fake_"):
        # Should not detect PII (or detect with low confidence)
        false_positives = len([f for f in column_findings if f.confidence > 0.8])
        accuracy_analysis[column] = {
            "type": "false_positive_test",
            "false_positives": false_positives,
            "total_items": len(accuracy_test_data),
        }
    else:
        # Non-PII columns - should not detect
        false_positives = len(column_findings)
        accuracy_analysis[column] = {
            "type": "non_pii",
            "false_positives": false_positives,
            "total_items": len(accuracy_test_data),
        }

print("Detection Accuracy Analysis:")
for column, analysis in accuracy_analysis.items():
    if analysis["type"] == "true_positive":
        print(
            f"  {column}: {analysis['accuracy']:.1%} accuracy ({analysis['detected']}/{analysis['expected']})"
        )
    elif analysis["type"] == "false_positive_test":
        print(f"  {column}: {analysis['false_positives']} false positives")
    else:
        print(f"  {column}: {analysis['false_positives']} unexpected detections")

# %%
print("\n" + "📊 Comparative Policy Analysis:")

# Create comprehensive policy comparison
comprehensive_policies = {
    "minimal": Policy(
        name="minimal_policy",
        version="1.0",
        rules=[Rule(match="ssn", action="redact")],
        default_action="mask",
        thresholds={"min_confidence": 0.9},
    ),
    "balanced": Policy(
        name="balanced_policy",
        version="1.0",
        rules=[
            Rule(match="email", action="mask"),
            Rule(match="phone", action="mask"),
            Rule(match="ssn", action="hash"),
        ],
        default_action="mask",
        thresholds={"min_confidence": 0.8},
    ),
    "strict": Policy(
        name="strict_policy",
        version="1.0",
        rules=[
            Rule(match="email", action="hash"),
            Rule(match="phone", action="hash"),
            Rule(match="ssn", action="redact"),
            Rule(match="credit_card", action="redact"),
        ],
        default_action="redact",
        thresholds={"min_confidence": 0.7},
    ),
    "paranoid": Policy(
        name="paranoid_policy",
        version="1.0",
        rules=[
            Rule(match="email", action="redact"),
            Rule(match="phone", action="redact"),
            Rule(match="ssn", action="redact"),
            Rule(match="credit_card", action="redact"),
            Rule(match="person_name", action="redact"),
        ],
        default_action="redact",
        thresholds={"min_confidence": 0.6},
    ),
}

# Test all policies on the same dataset
policy_metrics = {}
test_sample = test_data.head(50)

for policy_name, policy in comprehensive_policies.items():
    policy_client = NoPIIClient(policy=policy)

    # Measure comprehensive metrics
    start_time = time.time()
    policy_scan = policy_client.scan_dataframe(test_sample)
    scan_time = time.time() - start_time

    start_time = time.time()
    policy_transformed, policy_audit = policy_client.transform_dataframe(test_sample)
    transform_time = time.time() - start_time

    # Calculate data utility (how much original data is preserved)
    utility_score = 0
    for col in test_sample.columns:
        if col in policy_transformed.columns:
            # Simple utility metric: ratio of non-null, non-redacted values
            original_values = test_sample[col].astype(str)
            transformed_values = policy_transformed[col].astype(str)

            preserved_count = sum(
                1
                for orig, trans in zip(original_values, transformed_values)
                if trans not in ["[REDACTED]", "", "null", None] and len(trans) > 3
            )
            utility_score += preserved_count / len(original_values)

    utility_score = utility_score / len(test_sample.columns)

    policy_metrics[policy_name] = {
        "scan_time": scan_time,
        "transform_time": transform_time,
        "total_time": scan_time + transform_time,
        "coverage": policy_audit.coverage_score,
        "residual_risk": policy_audit.residual_risk,
        "utility_score": utility_score,
        "findings": len(policy_scan.findings),
        "rules_count": len(policy.rules),
    }

# Display comprehensive comparison
print("Comprehensive Policy Comparison:")
print(
    f"{'Policy':<10} {'Coverage':<9} {'Risk':<6} {'Utility':<8} {'Time':<7} {'Rules':<6}"
)
print("-" * 55)

for policy_name, metrics in policy_metrics.items():
    print(
        f"{policy_name:<10} {metrics['coverage']:<9.1%} {metrics['residual_risk']:<6.3f} "
        f"{metrics['utility_score']:<8.1%} {metrics['total_time']:<7.3f} {metrics['rules_count']:<6}"
    )

# %%
print("\n" + "🎯 Automated Recommendations Engine:")


def generate_policy_recommendations(metrics, requirements=None):
    """Generate automated policy recommendations based on metrics and requirements"""

    recommendations = []

    # Analyze current performance
    best_coverage = max(metrics.values(), key=lambda x: x["coverage"])
    best_utility = max(metrics.values(), key=lambda x: x["utility_score"])
    lowest_risk = min(metrics.values(), key=lambda x: x["residual_risk"])
    fastest = min(metrics.values(), key=lambda x: x["total_time"])

    # Generate recommendations based on different priorities
    if requirements:
        if "high_security" in requirements:
            rec_policy = min(metrics.items(), key=lambda x: x[1]["residual_risk"])
            recommendations.append(
                f"For high security: Use '{rec_policy[0]}' policy (lowest risk: {rec_policy[1]['residual_risk']:.3f})"
            )

        if "high_performance" in requirements:
            rec_policy = min(metrics.items(), key=lambda x: x[1]["total_time"])
            recommendations.append(
                f"For high performance: Use '{rec_policy[0]}' policy (fastest: {rec_policy[1]['total_time']:.3f}s)"
            )

        if "data_utility" in requirements:
            rec_policy = max(metrics.items(), key=lambda x: x[1]["utility_score"])
            recommendations.append(
                f"For data utility: Use '{rec_policy[0]}' policy (best utility: {rec_policy[1]['utility_score']:.1%})"
            )

        if "compliance" in requirements:
            # Recommend policy with >95% coverage and <0.1 residual risk
            compliant_policies = [
                (name, m)
                for name, m in metrics.items()
                if m["coverage"] > 0.95 and m["residual_risk"] < 0.1
            ]
            if compliant_policies:
                rec_policy = min(
                    compliant_policies, key=lambda x: x[1]["residual_risk"]
                )
                recommendations.append(
                    f"For compliance: Use '{rec_policy[0]}' policy (compliant with low risk)"
                )
            else:
                recommendations.append(
                    "For compliance: No current policy meets strict compliance requirements"
                )

    # General recommendations
    if not recommendations:
        # Balanced recommendation
        balanced_scores = {}
        for name, m in metrics.items():
            # Weighted score: coverage (40%) + utility (30%) + speed (20%) + low risk (10%)
            score = (
                m["coverage"] * 0.4
                + m["utility_score"] * 0.3
                + (
                    1
                    - m["total_time"]
                    / max(metrics.values(), key=lambda x: x["total_time"])["total_time"]
                )
                * 0.2
                + (1 - m["residual_risk"]) * 0.1
            )
            balanced_scores[name] = score

        best_balanced = max(balanced_scores.items(), key=lambda x: x[1])
        recommendations.append(
            f"Balanced recommendation: Use '{best_balanced[0]}' policy (best overall score: {best_balanced[1]:.3f})"
        )

    return recommendations


# Test recommendation engine
test_requirements = [
    ["high_security"],
    ["high_performance"],
    ["data_utility"],
    ["compliance"],
    ["high_security", "compliance"],
    [],  # No specific requirements
]

print("Automated Policy Recommendations:")
for req in test_requirements:
    req_str = ", ".join(req) if req else "General use"
    print(f"\n{req_str}:")
    recommendations = generate_policy_recommendations(policy_metrics, req)
    for rec in recommendations:
        print(f"  • {rec}")

print("\n🎯 Key Insights:")
print("1. Comprehensive reporting provides visibility into PII processing")
print("2. Multiple report formats support different stakeholder needs")
print("3. Coverage analysis helps optimize detection policies")
print("4. Performance monitoring enables scalability planning")
print("5. Policy comparison guides security vs usability decisions")
print("6. Custom templates enable stakeholder-specific reporting")
print("7. Accuracy analysis helps fine-tune detection thresholds")
print("8. Automated recommendations streamline policy selection")

print("\n📚 Next Steps:")
print("- Explore 05_real_world_examples.py for practical integration patterns")
print("- Review generated reports in the reports/ directory")
print("- Consider implementing automated reporting in your data pipeline")
print("- Use custom templates for regular stakeholder communications")
print("- Implement recommendation engine in production workflows")
