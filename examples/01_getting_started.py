# %%
"""
Getting Started with NoPII
==========================

This example covers the fundamentals of using the nopii package:
- Basic PII detection and transformation
- Understanding policies and rules
- Working with different data formats

Run each cell with Shift+Enter or your IDE's cell execution command.
"""

import pandas as pd

# %%
# Import the main nopii components
from nopii import NoPIIClient, create_default_policy, Policy, Rule

print("✅ Successfully imported nopii")

# %%
# Create a client with the default policy
client = NoPIIClient()

print(f"📋 Client initialized with policy: {client.current_policy.name}")
print(f"🔍 Available detectors: {len(client.list_detectors())}")
print(f"🔧 Available transformers: {len(client.list_transformers())}")

# %%
# Create sample data with various PII types
sample_data = pd.DataFrame(
    {
        "name": ["John Doe", "Jane Smith", "Bob Johnson"],
        "email": ["john.doe@example.com", "jane.smith@company.org", "bob@test.com"],
        "phone": ["555-123-4567", "555-987-6543", "5551234567"],
        "ssn": ["123-45-6789", "987-65-4321", "111-22-3333"],
        "credit_card": ["4111111111111111", "5555555555554444", "4000000000000002"],
        "notes": ["Customer since 2020", "VIP member", "New account"],
    }
)

print("📊 Sample DataFrame:")
print(sample_data)

# %%
# Perform a quick scan to detect PII
print("\n🔍 Quick PII Scan Results:")
scan_results = client.quick_scan(sample_data)

print(f"Total PII findings: {scan_results['total_findings']}")
print(f"PII types detected: {scan_results['pii_types']}")
print(f"Affected columns: {scan_results['affected_columns']}")
print(f"Coverage score: {scan_results['coverage_score']:.1%}")
print(f"High confidence findings: {scan_results['high_confidence_findings']}")

# %%
# Perform detailed scanning for more information
print("\n🔍 Detailed Scan Results:")
detailed_results = client.scan_dataframe(sample_data)

print(f"Dataset: {detailed_results.dataset_name}")
print(f"Total findings: {len(detailed_results.findings)}")

# Show first few findings
for i, finding in enumerate(detailed_results.findings[:5]):  # Show first 5 findings
    print(
        f"  Finding {i + 1}: {finding.type} in column '{finding.column}' "
        f"(confidence: {finding.confidence:.1%})"
    )

# %%
# Transform the data using the default policy
print("\n🛡️ Transforming Data:")
transformed_df, audit_report = client.transform_dataframe(sample_data)

print("Original vs Transformed:")
print("\nOriginal:")
print(sample_data.head(2))
print("\nTransformed:")
print(transformed_df.head(2))

print("\n📊 Transformation Summary:")
print(f"Coverage score: {audit_report.coverage_score:.1%}")
print(f"Residual risk: {audit_report.residual_risk}")
print(f"Total findings: {audit_report.summary_stats['total_findings']}")
print(f"Processing time: {audit_report.performance_metrics['total_duration']:.3f}s")

# %%
# Understanding and customizing policies
print("\n📋 Understanding Policies:")

# Examine the default policy
default_policy = create_default_policy()
print(f"Default policy: {default_policy.name} v{default_policy.version}")
print(f"Default action: {default_policy.default_action}")
print(f"Number of rules: {len(default_policy.rules)}")

print("\nDefault policy rules:")
for i, rule in enumerate(default_policy.rules[:3]):  # Show first 3 rules
    print(f"  Rule {i + 1}: {rule.match} → {rule.action}")
    if rule.options:
        print(f"    Options: {rule.options}")

# %%
# Create a custom policy for different transformation needs
print("\n" + "🔧 Creating Custom Policy:")

# Create a policy that redacts emails but masks everything else
custom_rules = [
    Rule(match="email", action="redact"),
    Rule(
        match="phone",
        action="mask",
        options={"mask_char": "X", "preserve_format": True},
    ),
    Rule(match="ssn", action="hash"),
    Rule(match="credit_card", action="mask", options={"show_last": 4}),
]

custom_policy = Policy(
    name="custom_demo_policy",
    version="1.0",
    description="Demo policy with mixed transformations",
    rules=custom_rules,
    default_action="mask",
)

# %%
# Use the custom policy
print("\n🎯 Using Custom Policy:")
custom_client = NoPIIClient(policy=custom_policy)

# Transform with custom policy
custom_transformed_df, custom_audit = custom_client.transform_dataframe(sample_data)

print("Comparison of transformations:")
print("\nDefault policy result:")
print(transformed_df[["email", "phone", "ssn"]].head(2))
print("\nCustom policy result:")
print(custom_transformed_df[["email", "phone", "ssn"]].head(2))

# %%
# Working with text data
print("\n📝 Working with Text Data:")

sample_text = "Contact John Doe at john.doe@example.com or call 555-123-4567 for more information."

# Scan text
text_findings = client.scan_text(sample_text)
print(f"Found {len(text_findings)} PII items in text:")
for finding in text_findings:
    print(
        f"  - {finding['type']}: '{finding['value']}' (confidence: {finding['confidence']:.1%})"
    )

# Transform text
transformed_text = client.transform_text(sample_text)
print(f"\nOriginal: {sample_text}")
print(f"Transformed: {transformed_text}")

# %%
# Key takeaways and next steps
print("\n" + "🎯 Key Takeaways:")
print("1. NoPIIClient provides easy access to PII detection and transformation")
print("2. quick_scan() gives a fast overview, scan_dataframe() provides details")
print("3. Policies control how different PII types are transformed")
print("4. Custom policies allow fine-tuned control over transformations")
print("5. The package works with DataFrames, text, and other data formats")

print("\n📚 Next Steps:")
print("- Explore 02_detectors_and_transformers.py for detector details")
print("- See 03_advanced_policies.py for complex policy configurations")
print("- Check 04_reporting_and_analysis.py for audit capabilities")
print("- Review 05_real_world_examples.py for practical use cases")
