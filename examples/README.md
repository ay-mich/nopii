# NoPII Examples

A collection of practical examples demonstrating how to use the NoPII library for PII detection, transformation, and data privacy protection.

## 🚀 Quick Start

1. **Install NoPII**: Run `pip install -e .[pandas,report-html]` from the repository root, then `pip install -r examples/requirements.txt`.
2. **Run any example**: Run `python examples/01_getting_started.py` from the repository root.
3. **Check outputs**: Generated files will be in the `examples/outputs/` directory.

## 📁 Directory Structure

```
├── 01_getting_started.py             # Basic PII detection and transformation
├── 02_detectors_and_transformers.py  # Exploring different detectors and transformers
├── 03_advanced_policies.py           # Custom policies and advanced configurations
├── 04_reporting_and_analysis.py      # Comprehensive reporting and analysis
├── 05_real_world_examples.py         # Production-ready patterns and best practices
├── 06_compliance_and_governance.py      # Regulatory compliance (GDPR, HIPAA, CCPA)
├── requirements.txt                  # Dependencies for examples
├── README.md                         # This file
└── outputs/                          # Generated outputs (created when scripts run)
    ├── compliance_outputs/           # Compliance reports and governance artifacts
    ├── data/                         # Transformed datasets and sample data
    ├── policies/                     # Generated policy files
    ├── reports/                      # HTML, JSON, and Markdown reports
    └── sample_data/                  # Sample datasets for testing
```

## 📚 Examples Overview

### 1. Getting Started (`01_getting_started.py`)

- Basic PII detection in DataFrames
- Simple transformations (redaction, masking)
- Understanding confidence scores
- Working with different data types

### 2. Detectors and Transformers (`02_detectors_and_transformers.py`)

- Exploring built-in PII detectors
- Comparing transformation methods
- Custom detector configurations
- Performance considerations

### 3. Advanced Policies (`03_advanced_policies.py`)

- Creating custom detection policies
- Policy inheritance and composition
- Environment-specific configurations
- Policy validation and testing

### 4. Reporting and Analysis (`04_reporting_and_analysis.py`)

- Comprehensive PII analysis reports
- Risk assessment and scoring
- Data quality metrics
- Export formats (HTML, JSON, Markdown)

### 5. Real-World Examples (`05_real_world_examples.py`)

- Production-ready patterns
- Data pipeline integration
- Configuration management
- Performance optimization
- Best practices and checklists

### 6. Compliance and Governance (`06_compliance_and_governance.py`)

- Regulatory compliance frameworks (GDPR, HIPAA, CCPA)
- Automated compliance policy creation
- Audit trail generation and reporting
- Data governance dashboard metrics
- Breach notification and consumer request workflows

## 🔧 Requirements

- Python 3.8+
- NoPII library
- pandas, sqlite3

## 📄 License

These examples are provided under the Apache License, Version 2.0. See the main `LICENSE` file for details.
