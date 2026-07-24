# %%
"""
Detectors and Transformers Deep Dive
====================================

This example explores the detection and transformation capabilities of nopii:
- Available PII detectors and their capabilities
- Transformation methods and options
- Testing different PII types and edge cases

Run each cell with Shift+Enter or your IDE's cell execution command.
"""

import pandas as pd
from nopii import (
    NoPIIClient,
    DetectorRegistry,
    TransformRegistry,
    create_default_policy,
)

# %%
# Explore available detectors
print("🔍 Available PII Detectors:")

detector_registry = DetectorRegistry()
detectors = detector_registry.list_detectors()
print(f"Total detectors: {len(detectors)}")

detector_info = detector_registry.get_detector_info()
for info in detector_info:
    print(f"\n📋 {info['name']}:")
    print(f"  - PII Type: {info['pii_type']}")
    print(f"  - Description: {info.get('description', 'No description')}")

# %%
# Explore available transformers
print("\n🔧 Available Transformers:")

transform_registry = TransformRegistry()
transformers = transform_registry.list_transformers()
print(f"Total transformers: {len(transformers)}")

transformer_info = transform_registry.get_transformer_info()
if isinstance(transformer_info, list):
    for info in transformer_info:
        print(f"\n📋 {info['name']}:")
        print(f"  - Description: {info.get('description', 'No description')}")

# %%
# Create comprehensive test data for all PII types
test_data = pd.DataFrame(
    {
        # Email addresses - various formats
        "emails": [
            "john.doe@example.com",
            "jane_smith@company.org",
            "test.email+tag@domain.co.uk",
            "user123@subdomain.example.net",
        ],
        # Phone numbers - different formats
        "phones": ["555-123-4567", "(555) 987-6543", "+1-555-111-2222", "555.444.3333"],
        # Social Security Numbers
        "ssns": ["123-45-6789", "987-65-4321", "111-22-3333", "555-44-6666"],
        # Credit card numbers
        "credit_cards": [
            "4111-1111-1111-1111",  # Visa
            "5555-5555-5555-4444",  # Mastercard
            "3782-822463-10005",  # Amex
            "6011-1111-1111-1117",  # Discover
        ],
        # Names
        "names": ["John Smith", "Mary Johnson", "Robert Williams", "Jennifer Brown"],
        # IP addresses
        "ip_addresses": ["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.1"],
        # Mixed content column
        "mixed_content": [
            "Contact John at john@example.com or 555-123-4567",
            "SSN: 123-45-6789, Card: 4111-1111-1111-1111",
            "IP: 192.168.1.1, Email: test@domain.com",
            "Phone: (555) 987-6543, Name: Jane Doe",
        ],
    }
)

print("📊 Test Data Created:")
print(f"Rows: {len(test_data)}, Columns: {len(test_data.columns)}")
print(test_data.head(2))

# %%
# Test detection capabilities
print("\n🔍 Testing Detection Capabilities:")

client = NoPIIClient()
scan_results = client.scan_dataframe(test_data)

print(f"Total findings: {len(scan_results.findings)}")

# Group findings by PII type
pii_counts = {}
for finding in scan_results.findings:
    pii_counts[finding.type] = pii_counts.get(finding.type, 0) + 1

print("\nFindings by PII type:")
for pii_type, count in sorted(pii_counts.items()):
    print(f"  {pii_type}: {count} findings")

# %%
# Test individual detector performance
print("\n🎯 Individual Detector Testing:")

# Test specific columns with expected PII types
test_cases = [
    ("emails", "email"),
    ("phones", "phone"),
    ("ssns", "ssn"),
    ("credit_cards", "credit_card"),
    ("names", "name"),
    ("ip_addresses", "ip_address"),
]

for column, expected_type in test_cases:
    if column in test_data.columns:
        column_data = pd.DataFrame({column: test_data[column]})
        results = client.scan_dataframe(column_data)

        detected_types = [f.type for f in results.findings]
        expected_count = len(test_data[column])
        actual_count = len([t for t in detected_types if t == expected_type])

        print(f"{column}: {actual_count}/{expected_count} detected as {expected_type}")

# %%
# Explore transformation methods
print("\n🛡️ Transformation Methods:")

# Test different transformation actions
transformation_tests = [
    ("mask", "Mask with asterisks"),
    ("redact", "Replace with placeholder"),
    ("hash", "One-way hash transformation"),
    ("tokenize", "Reversible tokenization"),
    ("nullify", "Replace with null values"),
]

sample_email_data = pd.DataFrame(
    {"email": ["john.doe@example.com", "jane.smith@company.org"]}
)

for action, description in transformation_tests:
    print(f"\n{action.upper()}: {description}")

    # Create a simple policy for this transformation
    from nopii import Policy, Rule

    test_policy = Policy(
        name=f"test_{action}",
        version="1.0",
        rules=[Rule(match="email", action=action)],
        default_action=action,
    )

    test_client = NoPIIClient(policy=test_policy)
    transformed_df, _ = test_client.transform_dataframe(sample_email_data)

    print(f"  Original: {sample_email_data['email'].iloc[0]}")
    print(f"  Transformed: {transformed_df['email'].iloc[0]}")

# %%
# Advanced transformation options
print("\n⚙️ Advanced Transformation Options:")

# Test masking with different options
masking_options = [
    {"mask_char": "*", "preserve_format": True},
    {"mask_char": "X", "preserve_format": False},
    {"show_first": 2, "show_last": 2},
    {"mask_char": "#", "show_last": 4},
]

sample_phone_data = pd.DataFrame({"phone": ["555-123-4567"]})

for i, options in enumerate(masking_options, 1):
    print(f"\nMasking Option {i}: {options}")

    test_policy = Policy(
        name=f"mask_test_{i}",
        version="1.0",
        rules=[Rule(match="phone", action="mask", options=options)],
        default_action="mask",
    )

    test_client = NoPIIClient(policy=test_policy)
    transformed_df, _ = test_client.transform_dataframe(sample_phone_data)

    print(f"  Original: {sample_phone_data['phone'].iloc[0]}")
    print(f"  Transformed: {transformed_df['phone'].iloc[0]}")

# %%
# Test mixed content detection and transformation
print("\n🔀 Mixed Content Processing:")

mixed_data = pd.DataFrame(
    {
        "description": [
            "Contact John Doe at john.doe@example.com or call 555-123-4567",
            "Customer SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111",
            "Server IP: 192.168.1.1, Admin email: admin@company.com",
        ]
    }
)

print("Original mixed content:")
for i, text in enumerate(mixed_data["description"]):
    print(f"  {i + 1}. {text}")

# Scan mixed content
mixed_results = client.scan_dataframe(mixed_data)
print(f"\nDetected {len(mixed_results.findings)} PII items in mixed content:")
for finding in mixed_results.findings:
    print(
        f"  - {finding.type}: '{finding.value}' (confidence: {finding.confidence:.1%})"
    )

# Transform mixed content
transformed_mixed, _ = client.transform_dataframe(mixed_data)
print("\nTransformed mixed content:")
for i, text in enumerate(transformed_mixed["description"]):
    print(f"  {i + 1}. {text}")

# %%
# Performance and confidence analysis
print("\n📊 Performance and Confidence Analysis:")

# Analyze confidence scores
confidences = [f.confidence for f in scan_results.findings]
if confidences:
    avg_confidence = sum(confidences) / len(confidences)
    min_confidence = min(confidences)
    max_confidence = max(confidences)

    print("Confidence scores:")
    print(f"  Average: {avg_confidence:.1%}")
    print(f"  Range: {min_confidence:.1%} - {max_confidence:.1%}")

    # Count high vs low confidence findings
    high_conf = sum(1 for c in confidences if c >= 0.8)
    medium_conf = sum(1 for c in confidences if 0.5 <= c < 0.8)
    low_conf = sum(1 for c in confidences if c < 0.5)

    print(f"  High confidence (≥80%): {high_conf}")
    print(f"  Medium confidence (50-79%): {medium_conf}")
    print(f"  Low confidence (<50%): {low_conf}")

# %%
print("\n🎯 Key Insights:")
print("1. NoPII includes comprehensive detectors for common PII types")
print("2. Multiple transformation methods available for different use cases")
print("3. Transformation options allow fine-tuned control over output")
print("4. Mixed content is automatically parsed for multiple PII types")
print("5. Confidence scores help assess detection reliability")

# %%
print("\n" + "🔧 Advanced Detector Configuration:")

# Test detector configuration capabilities
print("Testing detector configuration options...")

# Configure email detector for strict validation
try:
    detector_registry.configure_detector(
        "email",
        {"strict_validation": True, "allow_international": True, "min_confidence": 0.9},
    )
    print("✅ Email detector configured for strict validation")
except Exception as e:
    print(f"⚠️ Detector configuration not available: {e}")

# Test with international email formats
international_emails = pd.DataFrame(
    {
        "emails": [
            "user@münchen.de",  # German umlaut
            "test@москва.рф",  # Cyrillic domain
            "admin@東京.jp",  # Japanese characters
            "contact@café.fr",  # French accent
        ]
    }
)

print("\nTesting international email detection:")
intl_results = client.scan_dataframe(international_emails)
for finding in intl_results.findings:
    print(f"  - Detected: {finding.value} (confidence: {finding.confidence:.1%})")

# %%
print("\n🌍 Locale-Specific Detection:")

# Test locale support for different regions
locales_to_test = ["us", "eu", "asia"]

for locale in locales_to_test:
    print(f"\nTesting {locale.upper()} locale patterns:")
    try:
        # Attempt to load locale-specific patterns
        detector_registry.load_locale_pack(locale)
        print(f"✅ {locale.upper()} locale pack loaded")

        # Test with locale-specific data
        if locale == "eu":
            test_data_locale = pd.DataFrame(
                {"data": ["IBAN: DE89 3704 0044 0532 0130 00", "VAT: GB123456789"]}
            )
        elif locale == "asia":
            test_data_locale = pd.DataFrame(
                {"data": ["My Number: 1234-5678-9012", "Aadhar: 1234 5678 9012"]}
            )
        else:  # us
            test_data_locale = pd.DataFrame(
                {"data": ["SSN: 123-45-6789", "EIN: 12-3456789"]}
            )

        locale_results = client.scan_dataframe(test_data_locale)
        print(f"  Found {len(locale_results.findings)} locale-specific PII items")

    except Exception as e:
        print(f"⚠️ Locale {locale} not available: {e}")

# %%
print("\n📦 Batch Transformation Processing:")

# Create multiple datasets for batch processing
datasets = []
for i in range(3):
    dataset = pd.DataFrame(
        {
            "id": [f"user_{i}_{j}" for j in range(2)],
            "email": [f"user{i}_{j}@example.com" for j in range(2)],
            "phone": [f"555-{i}{j}00-{i}{j}01" for j in range(2)],
        }
    )
    datasets.append(dataset)

print(f"Created {len(datasets)} datasets for batch processing")
for i, df in enumerate(datasets):
    print(f"  Dataset {i + 1}: {len(df)} rows, {len(df.columns)} columns")

# Test batch transformation
try:
    batch_results = transform_registry.batch_transform(
        datasets, create_default_policy()
    )
    print(f"\n✅ Batch transformation completed on {len(batch_results)} datasets")

    for i, result in enumerate(batch_results):
        print(f"  Dataset {i + 1} transformed: {len(result)} rows")

except Exception as e:
    print(f"⚠️ Batch transformation not available: {e}")

    # Fallback: manual batch processing
    print("Using manual batch processing:")
    batch_client = NoPIIClient()

    for i, dataset in enumerate(datasets):
        transformed_df, _ = batch_client.transform_dataframe(dataset)
        print(f"  Dataset {i + 1}: {len(transformed_df)} rows transformed")
        print(f"    Sample: {transformed_df.iloc[0]['email']}")

# %%
print("\n⚡ Performance Benchmarking:")

# Create larger dataset for performance testing
large_dataset = pd.DataFrame(
    {
        "emails": [f"user{i}@domain{i % 10}.com" for i in range(1000)],
        "phones": [f"555-{i:03d}-{(i * 7) % 10000:04d}" for i in range(1000)],
        "names": [f"User {i} Name{i % 100}" for i in range(1000)],
    }
)

print(f"Created large dataset: {len(large_dataset)} rows")

# Benchmark different detection approaches
import time

# Single-threaded detection
start_time = time.time()
results_single = client.scan_dataframe(large_dataset)
single_time = time.time() - start_time

print("\nPerformance Results:")
print(
    f"  Single-threaded: {single_time:.2f}s for {len(results_single.findings)} findings"
)
print(f"  Rate: {len(large_dataset) / single_time:.0f} rows/second")

# Test column-by-column processing
start_time = time.time()
column_findings = 0
for column in large_dataset.columns:
    col_df = pd.DataFrame({column: large_dataset[column]})
    col_results = client.scan_dataframe(col_df)
    column_findings += len(col_results.findings)

column_time = time.time() - start_time

print(f"  Column-by-column: {column_time:.2f}s for {column_findings} findings")
print(f"  Rate: {len(large_dataset) / column_time:.0f} rows/second")

# %%
print("\n🎛️ Advanced Transformation Patterns:")

# Test complex transformation scenarios
complex_data = pd.DataFrame(
    {
        "customer_record": [
            "John Doe (john.doe@email.com) - Phone: 555-123-4567, SSN: 123-45-6789",
            "Jane Smith <jane@company.org> - Mobile: (555) 987-6543, Card: 4111-1111-1111-1111",
        ]
    }
)

# Create policy with different actions for different PII types
from nopii import Policy, Rule

complex_policy = Policy(
    name="complex_transformation",
    version="1.0",
    rules=[
        Rule(match="email", action="hash"),
        Rule(match="phone", action="mask", options={"show_last": 4}),
        Rule(match="ssn", action="redact"),
        Rule(match="credit_card", action="tokenize"),
    ],
    default_action="mask",
)

complex_client = NoPIIClient(policy=complex_policy)
transformed_complex, _ = complex_client.transform_dataframe(complex_data)

print("Complex transformation example:")
print(f"Original: {complex_data.iloc[0]['customer_record']}")
print(f"Transformed: {transformed_complex.iloc[0]['customer_record']}")

# %%
print("\n" + "🔍 Detection Accuracy Analysis:")

# Test edge cases and accuracy
edge_cases = pd.DataFrame(
    {
        "tricky_emails": [
            "not.an.email",  # Should not detect
            "almost@email",  # Should not detect
            "valid@email.com",  # Should detect
            "email@domain",  # Borderline case
        ],
        "phone_variants": [
            "555-1234",  # Too short
            "555-123-4567",  # Valid
            "1-555-123-4567",  # With country code
            "555.123.4567 ext 123",  # With extension
        ],
    }
)

edge_results = client.scan_dataframe(edge_cases)

print("Edge case detection results:")
for finding in edge_results.findings:
    print(
        f"  - {finding.type}: '{finding.value}' (confidence: {finding.confidence:.1%})"
    )

# Analyze false positives/negatives
expected_detections = {
    "valid@email.com": "email",
    "555-123-4567": "phone",
    "1-555-123-4567": "phone",
}

detected_values = {f.value: f.type for f in edge_results.findings}
print("\nAccuracy Analysis:")
print(f"Expected detections: {len(expected_detections)}")
print(f"Actual detections: {len(detected_values)}")

for expected_value, expected_type in expected_detections.items():
    if expected_value in detected_values:
        if detected_values[expected_value] == expected_type:
            print(f"  ✅ {expected_value}: Correctly detected as {expected_type}")
        else:
            print(
                f"  ❌ {expected_value}: Detected as {detected_values[expected_value]}, expected {expected_type}"
            )
    else:
        print(f"  ❌ {expected_value}: Not detected (expected {expected_type})")

print("\n" + "📚 Next Steps:")
print("- Explore 03_advanced_policies.py for complex policy configurations")
print("- See 04_reporting_and_analysis.py for detailed audit capabilities")
print("- Check 05_real_world_examples.py for practical integration patterns")
