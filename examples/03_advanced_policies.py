# %%
"""
Advanced Policy Configuration
============================

This example demonstrates advanced policy features:
- Creating complex policies with multiple rules
- Policy validation and loading from different sources
- Environment-specific and conditional policies
- Policy comparison and inheritance

Run each cell with Shift+Enter or your IDE's cell execution command.
"""

import pandas as pd
from pathlib import Path
from nopii import (
    NoPIIClient,
    Policy,
    Rule,
    create_default_policy,
    load_policy,
    save_policy,
)
from nopii.policy import load_policy_from_dict

# %%
# Examine the default policy structure
print("📋 Default Policy Analysis:")

default_policy = create_default_policy()
print(f"Name: {default_policy.name}")
print(f"Version: {default_policy.version}")
print(f"Description: {default_policy.description}")
print(f"Default action: {default_policy.default_action}")
print(f"Number of rules: {len(default_policy.rules)}")

print("\nDefault policy rules:")
for i, rule in enumerate(default_policy.rules, 1):
    print(f"  {i}. {rule.match} → {rule.action}")
    if rule.options:
        print(f"     Options: {rule.options}")
    if rule.override_confidence:
        print(f"     Confidence threshold: {rule.override_confidence}")

# %%
# Create a comprehensive custom policy
print("\n" + "🔧 Creating Custom Policy:")

# Define rules for different scenarios
custom_rules = [
    # High-security rules for sensitive data
    Rule(
        match="ssn",
        action="hash",
        options={"algorithm": "sha256", "salt": "custom_salt"},
        override_confidence=0.9,
    ),
    Rule(
        match="credit_card",
        action="mask",
        options={"show_last": 4, "mask_char": "*"},
        override_confidence=0.85,
    ),
    # Business-friendly rules for contact info
    Rule(
        match="email",
        action="mask",
        options={"preserve_domain": True, "mask_char": "*"},
        override_confidence=0.8,
    ),
    Rule(
        match="phone",
        action="mask",
        options={"preserve_format": True, "show_last": 4},
        override_confidence=0.8,
    ),
    # Conditional rules for different data types
    Rule(
        match="person_name",
        action="redact",
        columns=["customer_name", "employee_name"],  # Only specific columns
        override_confidence=0.7,
    ),
    Rule(match="ip_address", action="nullify", override_confidence=0.6),
]

# Create the policy
custom_policy = Policy(
    name="enterprise_policy",
    version="2.0",
    description="Enterprise policy with mixed security levels",
    rules=custom_rules,
    default_action="mask",
    thresholds={"min_confidence": 0.6},
)

print(f"✅ Created policy: {custom_policy.name}")
print(f"Rules defined: {len(custom_policy.rules)}")

# %%
# Test the custom policy
print("\n" + "🧪 Testing Custom Policy:")

# Create test data
test_data = pd.DataFrame(
    {
        "customer_name": ["John Doe", "Jane Smith"],
        "employee_name": ["Bob Johnson", "Alice Brown"],
        "contact_email": ["john@example.com", "jane@company.org"],
        "phone": ["555-123-4567", "555-987-6543"],
        "ssn": ["123-45-6789", "987-65-4321"],
        "credit_card": ["4111111111111111", "5555555555554444"],
        "server_ip": ["192.168.1.1", "10.0.0.1"],
        "notes": ["Regular customer", "VIP member"],
    }
)

print("Original data:")
print(test_data.head(2))

# Apply custom policy
custom_client = NoPIIClient(policy=custom_policy)
transformed_df, audit_report = custom_client.transform_dataframe(test_data)

print("\nTransformed data:")
print(transformed_df.head(2))

print("\nTransformation summary:")
print(f"Coverage: {audit_report.coverage_score:.1%}")
print(f"Residual risk: {audit_report.residual_risk}")

# %%
# Policy validation and error handling
print("\n✅ Policy Validation:")

# Test valid policy dictionary
valid_policy_dict = {
    "name": "test_policy",
    "version": "1.0",
    "description": "Test policy for validation",
    "rules": [
        {"match": "email", "action": "mask", "options": {"preserve_domain": True}},
        {"match": "phone", "action": "redact"},
    ],
    "default_action": "mask",
}

try:
    valid_policy = load_policy_from_dict(valid_policy_dict)
    print(f"✅ Valid policy created: {valid_policy.name}")
except Exception as e:
    print(f"❌ Policy validation failed: {e}")

# Test invalid policy (missing required fields)
invalid_policy_dict = {
    "name": "invalid_policy",
    # Missing version and rules
    "default_action": "invalid_action",  # Invalid action
}

try:
    invalid_policy = load_policy_from_dict(invalid_policy_dict)
    print(f"✅ Policy created: {invalid_policy.name}")
except Exception as e:
    print(f"❌ Expected validation error: {e}")

# %%
# Environment-specific policies
print("\n🌍 Environment-Specific Policies:")

# Development environment - more permissive
dev_policy_dict = {
    "name": "development_policy",
    "version": "1.0",
    "description": "Permissive policy for development",
    "rules": [
        {"match": "email", "action": "mask", "options": {"show_first": 3}},
        {"match": "phone", "action": "mask", "options": {"show_last": 4}},
        {"match": "ssn", "action": "mask", "options": {"show_last": 4}},
    ],
    "default_action": "mask",
    "thresholds": {"min_confidence": 0.5},
}

# Production environment - strict security
prod_policy_dict = {
    "name": "production_policy",
    "version": "1.0",
    "description": "Strict policy for production",
    "rules": [
        {"match": "email", "action": "hash"},
        {"match": "phone", "action": "hash"},
        {"match": "ssn", "action": "hash"},
        {"match": "credit_card", "action": "redact"},
    ],
    "default_action": "redact",
    "thresholds": {"min_confidence": 0.8},
}

dev_policy = load_policy_from_dict(dev_policy_dict)
prod_policy = load_policy_from_dict(prod_policy_dict)

print(
    f"Development policy: {dev_policy.name} (min confidence: {dev_policy.thresholds.get('min_confidence', 'N/A')})"
)
print(
    f"Production policy: {prod_policy.name} (min confidence: {prod_policy.thresholds.get('min_confidence', 'N/A')})"
)

# %%
# Compare policy effects
print("\n" + "⚖️ Policy Comparison:")

sample_data = pd.DataFrame(
    {
        "email": ["john.doe@example.com"],
        "phone": ["555-123-4567"],
        "ssn": ["123-45-6789"],
    }
)

print("Original data:")
print(sample_data)

# Test with development policy
dev_client = NoPIIClient(policy=dev_policy)
dev_result, _ = dev_client.transform_dataframe(sample_data)
print("\nDevelopment policy result:")
print(dev_result)

# Test with production policy
prod_client = NoPIIClient(policy=prod_policy)
prod_result, _ = prod_client.transform_dataframe(sample_data)
print("\nProduction policy result:")
print(prod_result)

# %%
# Save and load policies from files
print("\n" + "💾 Policy File Operations:")

# Save the policy to a file
script_dir = Path(__file__).parent
policy_file = script_dir / "outputs/policies/custom_enterprise_policy.yaml"
policy_file.parent.mkdir(parents=True, exist_ok=True)

try:
    save_policy(custom_policy, str(policy_file))
    print(f"✅ Policy saved to: {policy_file}")

    # Load policy from file
    loaded_policy = load_policy(str(policy_file))
    print(f"✅ Policy loaded: {loaded_policy.name} v{loaded_policy.version}")

    # Verify they're the same
    print(f"Rules match: {len(loaded_policy.rules) == len(custom_policy.rules)}")

except Exception as e:
    print(f"❌ File operation failed: {e}")

# %%
# Advanced rule configurations
print("\n" + "⚙️ Advanced Rule Configurations:")

# Rules with complex conditions
advanced_rules = [
    # Column-specific rules
    Rule(
        match="email",
        action="mask",
        columns=["customer_email"],  # Only apply to specific columns
        options={"preserve_domain": True},
    ),
    Rule(
        match="email",
        action="redact",
        columns=["employee_email"],  # Different action for different columns
    ),
    # High-confidence requirements
    Rule(
        match="person_name",
        action="mask",
        override_confidence=0.9,  # Only transform if very confident
        options={"show_first": 1, "show_last": 1},
    ),
    # Fallback rule for everything else
    Rule(
        match="*",  # Wildcard match
        action="nullify",
        override_confidence=0.95,  # Very high confidence required
    ),
]

advanced_policy = Policy(
    name="advanced_rules_policy",
    version="1.0",
    description="Policy with advanced rule configurations",
    rules=advanced_rules,
    default_action="mask",
)

print(f"✅ Created advanced policy with {len(advanced_policy.rules)} rules")

# Test advanced rules
test_advanced_data = pd.DataFrame(
    {
        "customer_email": ["customer@example.com"],
        "employee_email": ["employee@company.com"],
        "customer_name": ["John Doe"],
        "phone": ["555-123-4567"],
    }
)

advanced_client = NoPIIClient(policy=advanced_policy)
advanced_result, advanced_audit = advanced_client.transform_dataframe(
    test_advanced_data
)

print("\nAdvanced rules test:")
print("Original:")
print(test_advanced_data)
print("Transformed:")
print(advanced_result)

# %%
# Policy inheritance and merging concepts
print("\n" + "🔗 Policy Inheritance Concepts:")

# Base policy with common rules
base_policy_dict = {
    "name": "base_policy",
    "version": "1.0",
    "rules": [
        {"match": "email", "action": "mask"},
        {"match": "phone", "action": "mask"},
    ],
    "default_action": "mask",
}

# Specialized policy that extends base
specialized_policy_dict = {
    "name": "specialized_policy",
    "version": "1.0",
    "rules": [
        # Inherit base rules (conceptually)
        {"match": "email", "action": "mask"},
        {"match": "phone", "action": "mask"},
        # Add specialized rules
        {"match": "ssn", "action": "hash"},
        {"match": "credit_card", "action": "redact"},
    ],
    "default_action": "redact",  # Override default action
}

base_policy = load_policy_from_dict(base_policy_dict)
specialized_policy = load_policy_from_dict(specialized_policy_dict)

print(f"Base policy rules: {len(base_policy.rules)}")
print(f"Specialized policy rules: {len(specialized_policy.rules)}")
print(f"Base default action: {base_policy.default_action}")
print(f"Specialized default action: {specialized_policy.default_action}")

# %%
print("\n🏛️ Compliance-Specific Policies:")

# GDPR Compliance Policy
gdpr_policy_dict = {
    "name": "gdpr_compliance_policy",
    "version": "1.0",
    "description": "GDPR-compliant policy for EU data processing",
    "rules": [
        # Article 17 - Right to erasure
        {"match": "email", "action": "hash", "options": {"algorithm": "sha256"}},
        {"match": "person_name", "action": "redact"},
        {"match": "phone", "action": "hash", "options": {"algorithm": "sha256"}},
        {"match": "ip_address", "action": "nullify"},
        # Special categories of personal data (Article 9)
        {"match": "ssn", "action": "redact"},  # National identification
        {"match": "credit_card", "action": "redact"},  # Financial data
    ],
    "default_action": "redact",
    "thresholds": {"min_confidence": 0.8},
    "metadata": {
        "compliance_framework": "GDPR",
        "data_retention_days": 30,
        "lawful_basis": "legitimate_interest",
    },
}

# HIPAA Compliance Policy
hipaa_policy_dict = {
    "name": "hipaa_compliance_policy",
    "version": "1.0",
    "description": "HIPAA-compliant policy for healthcare data",
    "rules": [
        # Protected Health Information (PHI)
        {"match": "person_name", "action": "hash", "options": {"algorithm": "sha256"}},
        {"match": "email", "action": "hash", "options": {"algorithm": "sha256"}},
        {"match": "phone", "action": "mask", "options": {"show_last": 0}},
        {"match": "ssn", "action": "redact"},
        {"match": "ip_address", "action": "nullify"},
        # Medical record numbers, account numbers
        {"match": "credit_card", "action": "redact"},  # Account numbers
    ],
    "default_action": "redact",
    "thresholds": {"min_confidence": 0.9},  # Higher confidence for healthcare
    "metadata": {
        "compliance_framework": "HIPAA",
        "covered_entity": True,
        "minimum_necessary": True,
    },
}

# CCPA Compliance Policy
ccpa_policy_dict = {
    "name": "ccpa_compliance_policy",
    "version": "1.0",
    "description": "CCPA-compliant policy for California consumer data",
    "rules": [
        # Personal information categories
        {"match": "email", "action": "mask", "options": {"preserve_domain": True}},
        {"match": "person_name", "action": "mask", "options": {"show_first": 1}},
        {"match": "phone", "action": "mask", "options": {"show_last": 4}},
        {"match": "ip_address", "action": "mask"},
        {"match": "ssn", "action": "hash", "options": {"algorithm": "sha256"}},
        {"match": "credit_card", "action": "tokenize"},  # Allow for business purposes
    ],
    "default_action": "mask",
    "thresholds": {"min_confidence": 0.7},
    "metadata": {
        "compliance_framework": "CCPA",
        "consumer_rights": ["delete", "know", "opt_out"],
        "business_purpose": True,
    },
}

# Create compliance policies
gdpr_policy = load_policy_from_dict(gdpr_policy_dict)
hipaa_policy = load_policy_from_dict(hipaa_policy_dict)
ccpa_policy = load_policy_from_dict(ccpa_policy_dict)

print(f"✅ Created GDPR policy: {gdpr_policy.name}")
print(f"✅ Created HIPAA policy: {hipaa_policy.name}")
print(f"✅ Created CCPA policy: {ccpa_policy.name}")

# %%
print("\n🧪 Compliance Policy Testing:")

# Test data with various PII types
compliance_test_data = pd.DataFrame(
    {
        "patient_name": ["John Doe", "Jane Smith"],
        "email": ["john.doe@email.com", "jane.smith@hospital.org"],
        "phone": ["555-123-4567", "555-987-6543"],
        "ssn": ["123-45-6789", "987-65-4321"],
        "medical_record": ["MR123456", "MR789012"],
        "ip_address": ["192.168.1.100", "10.0.0.50"],
    }
)

print("Original compliance test data:")
print(compliance_test_data)

# Test each compliance framework
frameworks = [("GDPR", gdpr_policy), ("HIPAA", hipaa_policy), ("CCPA", ccpa_policy)]

for framework_name, policy in frameworks:
    print(f"\n{framework_name} Transformation:")
    client = NoPIIClient(policy=policy)
    transformed_df, audit = client.transform_dataframe(compliance_test_data)

    print(f"  Coverage: {audit.coverage_score:.1%}")
    print(f"  Residual risk: {audit.residual_risk}")
    print("  Sample transformation:")
    print(
        f"    Email: {compliance_test_data.iloc[0]['email']} → {transformed_df.iloc[0]['email']}"
    )
    print(
        f"    Name: {compliance_test_data.iloc[0]['patient_name']} → {transformed_df.iloc[0]['patient_name']}"
    )

# %%
print("\n🌐 Environment-Based Policy Loading:")

import os


def load_policy_from_environment():
    """Load policy based on environment variables"""
    env = os.getenv("NOPII_ENV", "development").lower()
    region = os.getenv("NOPII_REGION", "us").lower()
    compliance = os.getenv("NOPII_COMPLIANCE", "").lower()

    print(f"Environment: {env}")
    print(f"Region: {region}")
    print(f"Compliance: {compliance}")

    # Base policy selection by environment
    if env == "production":
        base_policy = prod_policy_dict.copy()
        base_policy["thresholds"]["min_confidence"] = 0.9
    elif env == "staging":
        base_policy = prod_policy_dict.copy()
        base_policy["thresholds"]["min_confidence"] = 0.8
    else:  # development
        base_policy = dev_policy_dict.copy()

    # Apply compliance overlay
    if compliance == "gdpr":
        base_policy.update(
            {
                "name": f"{env}_gdpr_policy",
                "rules": gdpr_policy_dict["rules"],
                "metadata": gdpr_policy_dict["metadata"],
            }
        )
    elif compliance == "hipaa":
        base_policy.update(
            {
                "name": f"{env}_hipaa_policy",
                "rules": hipaa_policy_dict["rules"],
                "metadata": hipaa_policy_dict["metadata"],
            }
        )
    elif compliance == "ccpa":
        base_policy.update(
            {
                "name": f"{env}_ccpa_policy",
                "rules": ccpa_policy_dict["rules"],
                "metadata": ccpa_policy_dict["metadata"],
            }
        )

    # Regional adjustments
    if region == "eu":
        # Stricter rules for EU
        base_policy["thresholds"]["min_confidence"] = min(
            0.9, base_policy["thresholds"].get("min_confidence", 0.8) + 0.1
        )
        base_policy["default_action"] = "redact"

    return load_policy_from_dict(base_policy)


# Test environment-based loading
print("\nTesting environment-based policy loading:")

# Simulate different environments
test_environments = [
    {"NOPII_ENV": "development", "NOPII_REGION": "us", "NOPII_COMPLIANCE": ""},
    {"NOPII_ENV": "production", "NOPII_REGION": "eu", "NOPII_COMPLIANCE": "gdpr"},
    {"NOPII_ENV": "production", "NOPII_REGION": "us", "NOPII_COMPLIANCE": "hipaa"},
]

for env_vars in test_environments:
    print(f"\n--- Environment: {env_vars} ---")

    # Set environment variables
    for key, value in env_vars.items():
        os.environ[key] = value

    try:
        env_policy = load_policy_from_environment()
        print(f"✅ Loaded policy: {env_policy.name}")
        print(f"   Default action: {env_policy.default_action}")
        print(
            f"   Min confidence: {env_policy.thresholds.get('min_confidence', 'N/A')}"
        )
        print(f"   Rules count: {len(env_policy.rules)}")
    except Exception as e:
        print(f"❌ Failed to load policy: {e}")

# Clean up environment variables
for key in ["NOPII_ENV", "NOPII_REGION", "NOPII_COMPLIANCE"]:
    os.environ.pop(key, None)

# %%
print("\n📊 Policy Performance Comparison:")

# Create test dataset for comparison
comparison_data = pd.DataFrame(
    {
        "email": ["user@example.com"] * 100,
        "phone": ["555-123-4567"] * 100,
        "ssn": ["123-45-6789"] * 100,
        "name": ["John Doe"] * 100,
    }
)

import time

policies_to_compare = [
    ("Default", create_default_policy()),
    ("Development", dev_policy),
    ("Production", prod_policy),
    ("GDPR", gdpr_policy),
    ("HIPAA", hipaa_policy),
    ("CCPA", ccpa_policy),
]

print(f"Comparing policies on {len(comparison_data)} rows:")

performance_results = []
for policy_name, policy in policies_to_compare:
    client = NoPIIClient(policy=policy)

    # Measure transformation time
    start_time = time.time()
    transformed_df, audit = client.transform_dataframe(comparison_data)
    end_time = time.time()

    performance_results.append(
        {
            "policy": policy_name,
            "time": end_time - start_time,
            "coverage": audit.coverage_score,
            "residual_risk": audit.residual_risk,
            "rules_count": len(policy.rules),
        }
    )

# Display results
print("\nPerformance Comparison Results:")
print(f"{'Policy':<12} {'Time (s)':<10} {'Coverage':<10} {'Risk':<8} {'Rules':<6}")
print("-" * 50)

for result in performance_results:
    print(
        f"{result['policy']:<12} {result['time']:<10.3f} {result['coverage']:<10.1%} {result['residual_risk']:<8} {result['rules_count']:<6}"
    )

# %%
print("\n" + "🔄 Dynamic Policy Adaptation:")


def create_adaptive_policy(
    data_sensitivity="medium", data_volume="medium", compliance_requirements=None
):
    """Create a policy that adapts based on data characteristics"""

    # Base configuration
    base_rules = [
        {"match": "email", "action": "mask"},
        {"match": "phone", "action": "mask"},
        {"match": "person_name", "action": "mask"},
    ]

    # Adjust based on sensitivity
    if data_sensitivity == "high":
        for rule in base_rules:
            rule["action"] = "hash"
        base_rules.append({"match": "ip_address", "action": "nullify"})
        min_confidence = 0.9
        default_action = "redact"
    elif data_sensitivity == "low":
        for rule in base_rules:
            if rule["action"] == "mask":
                rule["options"] = {"show_first": 2, "show_last": 2}
        min_confidence = 0.6
        default_action = "mask"
    else:  # medium
        min_confidence = 0.8
        default_action = "mask"

    # Adjust based on volume (performance considerations)
    if data_volume == "high":
        # Reduce confidence threshold for faster processing
        min_confidence = max(0.7, min_confidence - 0.1)

    # Apply compliance requirements
    if compliance_requirements:
        if "gdpr" in compliance_requirements:
            base_rules.extend(
                [
                    {"match": "ssn", "action": "redact"},
                    {"match": "credit_card", "action": "redact"},
                ]
            )
            min_confidence = 0.9
        if "hipaa" in compliance_requirements:
            default_action = "redact"
            min_confidence = 0.9

    policy_dict = {
        "name": f"adaptive_policy_{data_sensitivity}_{data_volume}",
        "version": "1.0",
        "description": f"Adaptive policy for {data_sensitivity} sensitivity, {data_volume} volume data",
        "rules": base_rules,
        "default_action": default_action,
        "thresholds": {"min_confidence": min_confidence},
    }

    return load_policy_from_dict(policy_dict)


# Test adaptive policies
print("Testing adaptive policy creation:")

adaptive_scenarios = [
    ("low", "high", None),
    ("high", "low", ["gdpr"]),
    ("medium", "medium", ["hipaa"]),
    ("high", "high", ["gdpr", "hipaa"]),
]

for sensitivity, volume, compliance in adaptive_scenarios:
    adaptive_policy = create_adaptive_policy(sensitivity, volume, compliance)
    print(f"\n{adaptive_policy.name}:")
    print(f"  Default action: {adaptive_policy.default_action}")
    print(f"  Min confidence: {adaptive_policy.thresholds['min_confidence']}")
    print(f"  Rules: {len(adaptive_policy.rules)}")

print("\n🎯 Key Takeaways:")
print("1. Policies provide flexible, rule-based PII transformation control")
print("2. Rules can be column-specific and confidence-threshold based")
print("3. Environment-specific policies enable different security levels")
print("4. Policy validation prevents configuration errors")
print("5. File-based policies enable version control and sharing")
print("6. Compliance-specific policies ensure regulatory adherence")
print("7. Environment-based loading supports DevOps workflows")
print("8. Adaptive policies can adjust to data characteristics")

print("\n📚 Next Steps:")
print("- Explore 04_reporting_and_analysis.py for audit capabilities")
print("- See 05_real_world_examples.py for practical integration patterns")
print("- Review policy YAML files in the policies/ directory")
print("- Check 06_compliance_and_governance.py for comprehensive compliance examples")
