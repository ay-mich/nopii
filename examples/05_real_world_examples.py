# %%
"""
Real-World Examples and Integration
===================================

This example demonstrates practical integration patterns and real-world scenarios:
- Integration with popular data frameworks (pandas, SQLAlchemy, Spark)
- CLI interface usage and automation
- Edge cases and error handling
- Production-ready patterns and best practices

Run each cell with Shift+Enter or your IDE's cell execution command.
"""

import pandas as pd
import numpy as np
import sqlite3
import json
from pathlib import Path
from nopii import NoPIIClient, Policy, Rule

# %%
# Real-world data processing pipeline
print("🏭 Real-World Data Processing Pipeline:")


# Simulate a typical data processing scenario
def create_realistic_dataset():
    """Create a realistic customer dataset with various data quality issues"""
    np.random.seed(42)

    # Generate realistic customer data
    customers = []
    for i in range(1, 201):
        customer = {
            "customer_id": f"CUST_{i:06d}",
            "first_name": np.random.choice(
                ["John", "Jane", "Mike", "Sarah", "David", "Lisa", ""]
            ),
            "last_name": np.random.choice(
                ["Smith", "Johnson", "Williams", "Brown", "Jones", None]
            ),
            "email": f"customer{i}@{'example' if i % 10 != 0 else 'invalid'}.com",
            "phone": f"555-{i:03d}-{(i * 7) % 10000:04d}" if i % 15 != 0 else None,
            "ssn": f"{i:03d}-{(i * 2) % 100:02d}-{(i * 3) % 10000:04d}"
            if i % 20 != 0
            else "",
            "date_of_birth": f"19{60 + i % 40}-{1 + i % 12:02d}-{1 + i % 28:02d}",
            "address": f"{i} Main St, City {i % 10}" if i % 25 != 0 else None,
            "credit_score": np.random.randint(300, 850) if i % 30 != 0 else None,
            "account_balance": round(np.random.uniform(-1000, 50000), 2),
            "notes": f"Customer notes for {i}" if i % 40 != 0 else "",
        }
        customers.append(customer)

    return pd.DataFrame(customers)


# Create realistic dataset
customer_data = create_realistic_dataset()
print(
    f"Created dataset: {len(customer_data)} rows, {len(customer_data.columns)} columns"
)
print(f"Data quality issues: {customer_data.isnull().sum().sum()} null values")

# Display sample with data quality issues
print("\nSample data (showing data quality issues):")
print(
    customer_data.head(10)[["customer_id", "first_name", "last_name", "email", "phone"]]
)

# %%
# Pandas integration with error handling
print("\n" + "🐼 Pandas Integration with Error Handling:")


def safe_pii_processing(df, dataset_name="unknown"):
    """Safely process PII data with comprehensive error handling"""
    try:
        client = NoPIIClient()

        # Validate input
        if df is None or df.empty:
            print(f"⚠️ Warning: Empty or None dataset '{dataset_name}'")
            return df, None

        print(f"Processing dataset '{dataset_name}' with {len(df)} rows...")

        # Handle missing values before processing
        df_clean = df.copy()

        # Scan for PII
        scan_results = client.scan_dataframe(df_clean, dataset_name=dataset_name)
        print(f"  Found {len(scan_results.findings)} PII findings")

        # Transform data
        transformed_df, audit_report = client.transform_dataframe(
            df_clean, dataset_name=dataset_name
        )
        print(
            f"  Transformation completed - Coverage: {audit_report.coverage_score:.1%}"
        )

        return transformed_df, audit_report

    except Exception as e:
        print(f"❌ Error processing dataset '{dataset_name}': {e}")
        return df, None


# Process customer data safely
transformed_customers, customer_audit = safe_pii_processing(
    customer_data, "customer_database"
)

# Show transformation results
if customer_audit:
    print("\nTransformation Results:")
    print(f"  Original rows: {len(customer_data)}")
    print(f"  Transformed rows: {len(transformed_customers)}")
    print(f"  Coverage score: {customer_audit.coverage_score:.1%}")
    print(f"  Processing time: {customer_audit.performance_metrics['total_time']:.3f}s")

# %%
# SQLAlchemy integration
print("\n🗃️ SQLAlchemy Integration:")


def process_database_table(connection_string, table_name, chunk_size=1000):
    """Process PII data from database in chunks"""
    try:
        # Create in-memory SQLite database for demo
        conn = sqlite3.connect(":memory:")

        # Insert sample data
        customer_data.to_sql("customers", conn, index=False, if_exists="replace")
        print(f"Created table 'customers' with {len(customer_data)} rows")

        # Process data in chunks
        client = NoPIIClient()
        processed_chunks = []

        # Read data in chunks
        for chunk_start in range(0, len(customer_data), chunk_size):
            query = f"SELECT * FROM customers LIMIT {chunk_size} OFFSET {chunk_start}"
            chunk_df = pd.read_sql_query(query, conn)

            if chunk_df.empty:
                break

            print(
                f"  Processing chunk {chunk_start // chunk_size + 1}: {len(chunk_df)} rows"
            )

            # Transform chunk
            transformed_chunk, _ = client.transform_dataframe(
                chunk_df,
                dataset_name=f"customers_chunk_{chunk_start // chunk_size + 1}",
            )
            processed_chunks.append(transformed_chunk)

        # Combine processed chunks
        final_df = pd.concat(processed_chunks, ignore_index=True)
        print(f"  Combined {len(processed_chunks)} chunks into {len(final_df)} rows")

        conn.close()
        return final_df

    except Exception as e:
        print(f"❌ Database processing error: {e}")
        return None


# Process database table
db_processed = process_database_table("sqlite:///:memory:", "customers")

# %%
# CLI interface demonstration
print("\n" + "💻 CLI Interface Demonstration:")


def demonstrate_cli_usage():
    """Demonstrate nopii CLI functionality"""

    # Create sample data files for CLI testing
    script_dir = Path(__file__).parent
    data_dir = script_dir / "outputs/data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # Save sample data
    sample_file = data_dir / "sample_customers.csv"
    customer_data.head(50).to_csv(sample_file, index=False)
    print(f"Created sample file: {sample_file}")

    # Create sample policy file
    policy_file = data_dir / "custom_policy.json"
    custom_policy = {
        "name": "demo_policy",
        "version": "1.0",
        "rules": [
            {"match": "email", "action": "mask", "options": {"show_first": 3}},
            {"match": "phone", "action": "mask", "options": {"show_last": 4}},
            {"match": "ssn", "action": "redact"},
        ],
        "default_action": "mask",
    }

    with open(policy_file, "w") as f:
        json.dump(custom_policy, f, indent=2)
    print(f"Created policy file: {policy_file}")

    # Demonstrate CLI commands (simulated)
    cli_commands = [
        f"nopii scan {sample_file}",
        f"nopii scan {sample_file} --policy {policy_file}",
        f"nopii transform {sample_file} --output {data_dir}/transformed_customers.csv",
        f"nopii report {sample_file} --format html --output {data_dir}/report.html",
    ]

    print("\nCLI Usage Examples:")
    for cmd in cli_commands:
        print(f"  $ {cmd}")

    # Try to run actual CLI command if available
    try:
        import sys
        from io import StringIO
        from nopii.cli import main

        # Capture CLI help output
        old_stdout = sys.stdout
        old_argv = sys.argv

        sys.stdout = StringIO()
        sys.argv = ["nopii", "--help"]

        try:
            main()
        except SystemExit:
            pass  # CLI help exits with code 0

        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        sys.argv = old_argv

        if output:
            print("\n✅ CLI is available:")
            print(output[:500] + "..." if len(output) > 500 else output)
        else:
            print("\n⚠️ CLI help output was empty")

    except Exception as e:
        print(f"\n⚠️ CLI test failed: {e}")

    # Demonstrate actual CLI functionality
    try:
        from nopii.cli import main
        import sys
        from io import StringIO

        print("\n🔧 Testing CLI scan command:")

        # Test scan command
        old_stdout = sys.stdout
        old_argv = sys.argv

        sys.stdout = StringIO()
        sys.argv = ["nopii", "scan", str(sample_file)]

        try:
            main()
        except SystemExit:
            pass

        scan_output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        sys.argv = old_argv

        if scan_output:
            print("Scan command executed successfully:")
            print(scan_output[:300] + "..." if len(scan_output) > 300 else scan_output)
        else:
            print("Scan command completed (no output captured)")

    except Exception as e:
        print(f"CLI scan test failed: {e}")


demonstrate_cli_usage()

# %%
# Edge cases and error handling
print("\n" + "🛡️ Edge Cases and Error Handling:")


def test_edge_cases():
    """Test various edge cases and error conditions"""

    edge_cases = {
        "empty_dataframe": pd.DataFrame(),
        "single_row": pd.DataFrame({"email": ["test@example.com"]}),
        "single_column": pd.DataFrame({"data": range(10)}),
        "all_nulls": pd.DataFrame({"col1": [None] * 5, "col2": [None] * 5}),
        "mixed_types": pd.DataFrame(
            {
                "numbers": [1, 2, 3, "four", None],
                "strings": ["a", "b", None, 4, "e"],
                "emails": [
                    "test@example.com",
                    None,
                    "invalid-email",
                    "",
                    "user@domain.com",
                ],
            }
        ),
        "unicode_data": pd.DataFrame(
            {
                "names": ["José García", "李小明", "محمد أحمد", "Müller", "Øyvind"],
                "emails": [
                    "josé@example.com",
                    "li@example.cn",
                    "ahmed@example.ae",
                    "muller@example.de",
                    "oyvind@example.no",
                ],
            }
        ),
        "large_text": pd.DataFrame(
            {
                "description": [
                    "This is a very long text " * 100 + " with email@example.com"
                ]
            }
        ),
    }

    client = NoPIIClient()

    for case_name, test_df in edge_cases.items():
        print(f"\n  Testing: {case_name}")
        try:
            if test_df.empty:
                print("    ⚠️ Skipping empty dataframe")
                continue

            scan_results = client.scan_dataframe(test_df, dataset_name=case_name)
            print(f"    ✅ Scan successful: {len(scan_results.findings)} findings")

            transformed_df, audit = client.transform_dataframe(
                test_df, dataset_name=case_name
            )
            print(f"    ✅ Transform successful: {audit.coverage_score:.1%} coverage")

        except Exception as e:
            print(f"    ❌ Error: {e}")


test_edge_cases()

# %%
# Production-ready patterns
print("\n🏗️ Production-Ready Patterns:")


class ProductionPIIProcessor:
    """Production-ready PII processor with logging, monitoring, and error handling"""

    def __init__(self, policy=None, enable_logging=True):
        self.client = NoPIIClient(policy=policy)
        self.enable_logging = enable_logging
        self.processing_stats = {
            "total_processed": 0,
            "total_findings": 0,
            "total_errors": 0,
            "processing_time": 0.0,
        }

    def process_batch(self, dataframes, batch_name="unknown"):
        """Process multiple dataframes as a batch"""
        import time

        start_time = time.time()
        results = []

        if self.enable_logging:
            print(
                f"🔄 Processing batch '{batch_name}' with {len(dataframes)} dataframes"
            )

        for i, df in enumerate(dataframes):
            try:
                if df is None or df.empty:
                    if self.enable_logging:
                        print(f"  ⚠️ Skipping empty dataframe {i + 1}")
                    continue

                # Process dataframe
                transformed_df, audit = self.client.transform_dataframe(
                    df, dataset_name=f"{batch_name}_df_{i + 1}"
                )

                results.append(
                    {
                        "index": i,
                        "original_rows": len(df),
                        "transformed_rows": len(transformed_df),
                        "coverage": audit.coverage_score,
                        "findings": len(audit.scan_results.findings)
                        if hasattr(audit, "scan_results")
                        else 0,
                        "dataframe": transformed_df,
                    }
                )

                # Update stats
                self.processing_stats["total_processed"] += len(df)
                if hasattr(audit, "scan_results"):
                    self.processing_stats["total_findings"] += len(
                        audit.scan_results.findings
                    )

                if self.enable_logging:
                    print(
                        f"  ✅ Processed dataframe {i + 1}: {len(df)} rows, "
                        f"{audit.coverage_score:.1%} coverage"
                    )

            except Exception as e:
                self.processing_stats["total_errors"] += 1
                if self.enable_logging:
                    print(f"  ❌ Error processing dataframe {i + 1}: {e}")

                results.append(
                    {
                        "index": i,
                        "error": str(e),
                        "dataframe": df,  # Return original on error
                    }
                )

        processing_time = time.time() - start_time
        self.processing_stats["processing_time"] += processing_time

        if self.enable_logging:
            print(f"✅ Batch '{batch_name}' completed in {processing_time:.3f}s")

        return results

    def get_stats(self):
        """Get processing statistics"""
        return self.processing_stats.copy()


# Demonstrate production processor
processor = ProductionPIIProcessor()

# Create multiple test dataframes
test_dataframes = [
    customer_data.head(50),
    customer_data.tail(30),
    pd.DataFrame({"emails": ["test1@example.com", "test2@example.com"]}),
    pd.DataFrame(),  # Empty dataframe
    None,  # None dataframe
]

# Process batch
batch_results = processor.process_batch(test_dataframes, "demo_batch")

# Show statistics
stats = processor.get_stats()
print("\nProcessing Statistics:")
for key, value in stats.items():
    if isinstance(value, float):
        print(f"  {key}: {value:.3f}")
    else:
        print(f"  {key}: {value}")

# %%
# Configuration management
print("\n⚙️ Configuration Management:")


def create_environment_configs():
    """Create different configurations for different environments"""

    configs = {
        "development": {
            "policy": Policy(
                name="dev_policy",
                version="1.0",
                rules=[
                    Rule(match="email", action="mask", options={"show_first": 5}),
                    Rule(match="phone", action="mask", options={"show_last": 4}),
                ],
                default_action="mask",
            ),
            "confidence_threshold": 0.7,
            "enable_logging": True,
            "batch_size": 100,
        },
        "staging": {
            "policy": Policy(
                name="staging_policy",
                version="1.0",
                rules=[
                    Rule(match="email", action="hash"),
                    Rule(match="phone", action="hash"),
                    Rule(match="ssn", action="redact"),
                ],
                default_action="hash",
            ),
            "confidence_threshold": 0.8,
            "enable_logging": True,
            "batch_size": 500,
        },
        "production": {
            "policy": Policy(
                name="prod_policy",
                version="1.0",
                rules=[
                    Rule(match="email", action="hash"),
                    Rule(match="phone", action="hash"),
                    Rule(match="ssn", action="redact"),
                    Rule(match="credit_card", action="redact"),
                ],
                default_action="redact",
            ),
            "confidence_threshold": 0.9,
            "enable_logging": False,
            "batch_size": 1000,
        },
    }

    return configs


# Demonstrate environment-specific processing
configs = create_environment_configs()

for env_name, config in configs.items():
    print(f"\n{env_name.upper()} Environment:")
    print(f"  Policy: {config['policy'].name}")
    print(f"  Rules: {len(config['policy'].rules)}")
    print(f"  Confidence threshold: {config['confidence_threshold']}")
    print(f"  Batch size: {config['batch_size']}")

# %%
# Integration with data pipelines
print("\n" + "🔄 Data Pipeline Integration:")


def create_pii_pipeline_stage(config):
    """Create a reusable PII processing stage for data pipelines"""

    def pii_stage(df, stage_name="pii_processing"):
        """Pipeline stage function"""
        try:
            client = NoPIIClient(policy=config["policy"])

            # Apply confidence threshold if specified
            if "confidence_threshold" in config:
                # Note: This would require client configuration support
                pass

            transformed_df, audit = client.transform_dataframe(
                df, dataset_name=stage_name
            )

            # Add pipeline metadata
            pipeline_metadata = {
                "stage": stage_name,
                "coverage": audit.coverage_score,
                "processing_time": audit.performance_metrics["total_time"],
                "findings_count": len(audit.scan_results.findings)
                if hasattr(audit, "scan_results")
                else 0,
            }

            return transformed_df, pipeline_metadata

        except Exception as e:
            print(f"❌ Pipeline stage '{stage_name}' failed: {e}")
            return df, {"stage": stage_name, "error": str(e)}

    return pii_stage


# Create pipeline stages for different environments
dev_stage = create_pii_pipeline_stage(configs["development"])
prod_stage = create_pii_pipeline_stage(configs["production"])

# Simulate pipeline execution
sample_data = customer_data.head(20)

print("Development Pipeline:")
dev_result, dev_metadata = dev_stage(sample_data, "dev_customer_processing")
print(f"  Coverage: {dev_metadata.get('coverage', 'N/A'):.1%}")
print(f"  Findings: {dev_metadata.get('findings_count', 'N/A')}")

print("\nProduction Pipeline:")
prod_result, prod_metadata = prod_stage(sample_data, "prod_customer_processing")
print(f"  Coverage: {prod_metadata.get('coverage', 'N/A'):.1%}")
print(f"  Findings: {prod_metadata.get('findings_count', 'N/A')}")

# %%
print("\n🎯 Key Takeaways:")
print("1. Always implement comprehensive error handling for production use")
print("2. Process data in chunks for large datasets to manage memory")
print("3. Use environment-specific configurations for different deployment stages")
print("4. Implement monitoring and logging for production PII processing")
print("5. Create reusable pipeline components for consistent processing")
print("6. Test edge cases thoroughly before production deployment")

print("\n📚 Best Practices:")
print("- Validate input data before processing")
print("- Implement proper logging and monitoring")
print("- Use appropriate batch sizes for your infrastructure")
print("- Test with realistic data that includes quality issues")
print("- Implement graceful degradation for processing errors")
print("- Regular auditing and policy updates")

# %%
print("\n" + "📁 Multi-Format File Processing:")

import xml.etree.ElementTree as ET


def process_csv_file(file_path, chunk_size=1000):
    """Process CSV files in chunks for memory efficiency"""
    client = NoPIIClient()
    processed_chunks = []

    try:
        # Read and process CSV in chunks
        for chunk_num, chunk in enumerate(pd.read_csv(file_path, chunksize=chunk_size)):
            print(f"  Processing chunk {chunk_num + 1} ({len(chunk)} rows)...")

            # Transform chunk
            transformed_chunk, audit = client.transform_dataframe(
                chunk, dataset_name=f"csv_chunk_{chunk_num}"
            )
            processed_chunks.append(
                {"data": transformed_chunk, "audit": audit, "chunk_num": chunk_num}
            )

        return processed_chunks

    except Exception as e:
        print(f"❌ Error processing CSV file: {e}")
        return []


def process_json_file(file_path):
    """Process JSON files with nested PII data"""
    client = NoPIIClient()

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # Flatten nested JSON for PII processing
        if isinstance(data, list):
            # Array of objects
            df = pd.json_normalize(data)
        else:
            # Single object or nested structure
            df = pd.json_normalize([data])

        print(f"  Flattened JSON to {len(df)} rows, {len(df.columns)} columns")

        # Process flattened data
        transformed_df, audit = client.transform_dataframe(df, dataset_name="json_data")

        return {
            "original_structure": data,
            "flattened_data": df,
            "transformed_data": transformed_df,
            "audit": audit,
        }

    except Exception as e:
        print(f"❌ Error processing JSON file: {e}")
        return None


def process_xml_file(file_path):
    """Process XML files by converting to structured data"""
    client = NoPIIClient()

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Convert XML to list of dictionaries
        records = []
        for element in root:
            record = {}
            for child in element:
                record[child.tag] = child.text
            records.append(record)

        if records:
            df = pd.DataFrame(records)
            print(f"  Converted XML to {len(df)} rows, {len(df.columns)} columns")

            # Process converted data
            transformed_df, audit = client.transform_dataframe(
                df, dataset_name="xml_data"
            )

            return {
                "original_xml": root,
                "converted_data": df,
                "transformed_data": transformed_df,
                "audit": audit,
            }
        else:
            print("  No records found in XML file")
            return None

    except Exception as e:
        print(f"❌ Error processing XML file: {e}")
        return None


# Create sample files for demonstration
script_dir = Path(__file__).parent
sample_dir = script_dir / "outputs/sample_data"
sample_dir.mkdir(parents=True, exist_ok=True)

# Create sample CSV
sample_csv_data = customer_data.head(100)
csv_file = sample_dir / "customers.csv"
sample_csv_data.to_csv(csv_file, index=False)
print(f"Created sample CSV: {csv_file}")

# Create sample JSON
sample_json_data = [
    {
        "id": 1,
        "personal_info": {
            "name": "John Doe",
            "email": "john.doe@example.com",
            "phone": "555-123-4567",
        },
        "account": {"ssn": "123-45-6789", "balance": 1500.00},
    },
    {
        "id": 2,
        "personal_info": {
            "name": "Jane Smith",
            "email": "jane.smith@example.com",
            "phone": "555-987-6543",
        },
        "account": {"ssn": "987-65-4321", "balance": 2500.00},
    },
]

json_file = sample_dir / "customers.json"
with open(json_file, "w") as f:
    json.dump(sample_json_data, f, indent=2)
print(f"Created sample JSON: {json_file}")

# Create sample XML
xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<customers>
    <customer>
        <id>1</id>
        <name>John Doe</name>
        <email>john.doe@example.com</email>
        <phone>555-123-4567</phone>
        <ssn>123-45-6789</ssn>
    </customer>
    <customer>
        <id>2</id>
        <name>Jane Smith</name>
        <email>jane.smith@example.com</email>
        <phone>555-987-6543</phone>
        <ssn>987-65-4321</ssn>
    </customer>
</customers>"""

xml_file = sample_dir / "customers.xml"
with open(xml_file, "w") as f:
    f.write(xml_content)
print(f"Created sample XML: {xml_file}")

# Process different file formats
print("\nProcessing CSV file:")
csv_results = process_csv_file(csv_file, chunk_size=50)
if csv_results:
    total_coverage = sum(chunk["audit"].coverage_score for chunk in csv_results) / len(
        csv_results
    )
    print(
        f"  Processed {len(csv_results)} chunks, average coverage: {total_coverage:.1%}"
    )

print("\nProcessing JSON file:")
json_result = process_json_file(json_file)
if json_result:
    print(f"  Coverage: {json_result['audit'].coverage_score:.1%}")
    print(f"  Findings: {len(json_result['audit'].scan_result.findings)}")

print("\nProcessing XML file:")
xml_result = process_xml_file(xml_file)
if xml_result:
    print(f"  Coverage: {xml_result['audit'].coverage_score:.1%}")
    print(f"  Findings: {len(xml_result['audit'].scan_result.findings)}")

# %%
print("\n" + "🌊 Streaming Data Processing:")

import time
import threading
from queue import Queue
from datetime import datetime


class StreamingPIIProcessor:
    """Process streaming data with real-time PII detection and transformation"""

    def __init__(self, batch_size=100, flush_interval=5.0):
        self.client = NoPIIClient()
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = []
        self.processed_count = 0
        self.error_count = 0
        self.last_flush = time.time()
        self.running = False
        self.results_queue = Queue()

    def add_record(self, record):
        """Add a single record to the processing buffer"""
        self.buffer.append(record)

        # Check if we should flush the buffer
        if (
            len(self.buffer) >= self.batch_size
            or time.time() - self.last_flush >= self.flush_interval
        ):
            self._flush_buffer()

    def _flush_buffer(self):
        """Process the current buffer of records"""
        if not self.buffer:
            return

        try:
            # Convert buffer to DataFrame
            df = pd.DataFrame(self.buffer)

            # Process the batch
            transformed_df, audit = self.client.transform_dataframe(
                df, dataset_name=f"stream_batch_{int(time.time())}"
            )

            # Store results
            result = {
                "timestamp": datetime.now(),
                "original_count": len(df),
                "transformed_data": transformed_df,
                "audit": audit,
                "processing_time": time.time() - self.last_flush,
            }

            self.results_queue.put(result)
            self.processed_count += len(df)

            print(
                f"  Processed batch: {len(df)} records, coverage: {audit.coverage_score:.1%}"
            )

        except Exception as e:
            self.error_count += len(self.buffer)
            print(f"  ❌ Error processing batch: {e}")

        finally:
            # Clear buffer and update timestamp
            self.buffer.clear()
            self.last_flush = time.time()

    def start_streaming(self):
        """Start the streaming processor"""
        self.running = True
        print("🌊 Streaming processor started")

    def stop_streaming(self):
        """Stop the streaming processor and flush remaining data"""
        self.running = False
        self._flush_buffer()  # Process any remaining data
        print(
            f"🛑 Streaming processor stopped. Processed: {self.processed_count}, Errors: {self.error_count}"
        )

    def get_results(self):
        """Get all processed results"""
        results = []
        while not self.results_queue.empty():
            results.append(self.results_queue.get())
        return results


# Simulate streaming data
def simulate_data_stream(processor, duration=10, records_per_second=20):
    """Simulate a stream of incoming data records"""
    start_time = time.time()
    record_id = 1

    while time.time() - start_time < duration and processor.running:
        # Generate a realistic record
        record = {
            "id": record_id,
            "timestamp": datetime.now().isoformat(),
            "user_email": f"user{record_id}@example.com",
            "phone": f"555-{record_id:03d}-{(record_id * 7) % 10000:04d}",
            "transaction_amount": round(np.random.uniform(10, 1000), 2),
            "ip_address": f"192.168.{record_id % 256}.{(record_id * 3) % 256}",
            "session_id": f"sess_{record_id:08d}",
        }

        processor.add_record(record)
        record_id += 1

        # Control the rate of data generation
        time.sleep(1.0 / records_per_second)


# Demonstrate streaming processing
print("Setting up streaming processor...")
stream_processor = StreamingPIIProcessor(batch_size=50, flush_interval=3.0)
stream_processor.start_streaming()

# Simulate data stream in a separate thread
print("Starting data stream simulation...")
stream_thread = threading.Thread(
    target=simulate_data_stream,
    args=(stream_processor, 8, 25),  # 8 seconds, 25 records/second
)
stream_thread.start()

# Monitor processing
time.sleep(10)  # Let it run for a bit

# Stop streaming
stream_processor.stop_streaming()
stream_thread.join()

# Get and analyze results
results = stream_processor.get_results()
print("\nStreaming Results:")
print(f"  Total batches processed: {len(results)}")
print(f"  Total records processed: {sum(r['original_count'] for r in results)}")

if results:
    avg_coverage = sum(r["audit"].coverage_score for r in results) / len(results)
    avg_processing_time = sum(r["processing_time"] for r in results) / len(results)
    print(f"  Average coverage: {avg_coverage:.1%}")
    print(f"  Average batch processing time: {avg_processing_time:.3f}s")

# %%
print("\n" + "🔗 Advanced Integration Patterns:")


# Apache Kafka integration pattern
def create_kafka_consumer_pattern():
    """Demonstrate Kafka consumer pattern for PII processing"""

    class MockKafkaConsumer:
        """Mock Kafka consumer for demonstration"""

        def __init__(self, topic):
            self.topic = topic
            self.messages = [
                {"user_id": i, "email": f"user{i}@example.com", "data": f"message {i}"}
                for i in range(1, 21)
            ]
            self.index = 0

        def poll(self, timeout=1000):
            if self.index < len(self.messages):
                msg = self.messages[self.index]
                self.index += 1
                return [msg]
            return []

        def close(self):
            pass

    # Kafka processing function
    def process_kafka_messages(topic_name, max_messages=20):
        consumer = MockKafkaConsumer(topic_name)
        processor = StreamingPIIProcessor(batch_size=5, flush_interval=2.0)
        processor.start_streaming()

        processed_messages = 0

        try:
            while processed_messages < max_messages:
                messages = consumer.poll()

                for message in messages:
                    processor.add_record(message)
                    processed_messages += 1

                if not messages:
                    time.sleep(0.1)  # Brief pause if no messages

        finally:
            processor.stop_streaming()
            consumer.close()

        return processor.get_results()

    return process_kafka_messages


# REST API integration pattern
def create_api_integration_pattern():
    """Demonstrate REST API integration for PII processing"""

    class PIIProcessingAPI:
        """Mock API service for PII processing"""

        def __init__(self):
            self.client = NoPIIClient()
            self.request_count = 0

        def process_request(self, data, request_id=None):
            """Process a single API request"""
            self.request_count += 1

            try:
                # Convert request data to DataFrame
                if isinstance(data, dict):
                    df = pd.DataFrame([data])
                elif isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    raise ValueError("Invalid data format")

                # Process the data
                transformed_df, audit = self.client.transform_dataframe(
                    df, dataset_name=f"api_request_{request_id or self.request_count}"
                )

                # Return API response
                return {
                    "status": "success",
                    "request_id": request_id or self.request_count,
                    "processed_records": len(transformed_df),
                    "coverage": audit.coverage_score,
                    "data": transformed_df.to_dict("records"),
                    "audit_summary": {
                        "findings": len(audit.scan_result.findings),
                        "processing_time": audit.performance_metrics.get(
                            "total_time", 0
                        ),
                    },
                }

            except Exception as e:
                return {
                    "status": "error",
                    "request_id": request_id or self.request_count,
                    "error": str(e),
                }

        def batch_process(self, requests):
            """Process multiple requests in batch"""
            results = []

            for i, request_data in enumerate(requests):
                result = self.process_request(request_data, f"batch_{i + 1}")
                results.append(result)

            return {
                "batch_status": "completed",
                "total_requests": len(requests),
                "successful": sum(1 for r in results if r["status"] == "success"),
                "failed": sum(1 for r in results if r["status"] == "error"),
                "results": results,
            }

    return PIIProcessingAPI()


# Database integration with connection pooling
def create_database_integration_pattern():
    """Demonstrate database integration with connection pooling"""

    class DatabasePIIProcessor:
        """Database processor with connection pooling simulation"""

        def __init__(self, pool_size=5):
            self.client = NoPIIClient()
            self.pool_size = pool_size
            self.active_connections = 0

        def process_table(self, table_name, connection_string, chunk_size=1000):
            """Process a database table in chunks"""

            # Simulate connection acquisition
            if self.active_connections >= self.pool_size:
                print("  ⏳ Waiting for available connection...")
                time.sleep(0.1)

            self.active_connections += 1

            try:
                # Simulate reading from database
                print(f"  📊 Processing table '{table_name}' in chunks of {chunk_size}")

                # For demo, use our customer data
                total_rows = len(customer_data)
                chunks_processed = 0

                for start_idx in range(0, total_rows, chunk_size):
                    end_idx = min(start_idx + chunk_size, total_rows)
                    chunk = customer_data.iloc[start_idx:end_idx]

                    # Process chunk
                    transformed_chunk, audit = self.client.transform_dataframe(
                        chunk, dataset_name=f"{table_name}_chunk_{chunks_processed}"
                    )

                    chunks_processed += 1
                    print(
                        f"    Chunk {chunks_processed}: {len(chunk)} rows, coverage: {audit.coverage_score:.1%}"
                    )

                return {
                    "table": table_name,
                    "total_rows": total_rows,
                    "chunks_processed": chunks_processed,
                    "status": "completed",
                }

            finally:
                # Release connection
                self.active_connections -= 1

    return DatabasePIIProcessor()


# Demonstrate integration patterns
print("Kafka Consumer Pattern:")
kafka_processor = create_kafka_consumer_pattern()
kafka_results = kafka_processor("user_events", max_messages=15)
print(f"  Processed {len(kafka_results)} Kafka message batches")

print("\nREST API Pattern:")
api_service = create_api_integration_pattern()

# Test single request
single_request = {
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "555-123-4567",
}
api_result = api_service.process_request(single_request)
print(
    f"  Single request: {api_result['status']}, coverage: {api_result.get('coverage', 0):.1%}"
)

# Test batch requests
batch_requests = [
    {"name": "Alice Smith", "email": "alice@example.com"},
    {"name": "Bob Johnson", "email": "bob@example.com", "ssn": "123-45-6789"},
    {"name": "Carol Brown", "phone": "555-987-6543"},
]
batch_result = api_service.batch_process(batch_requests)
print(
    f"  Batch processing: {batch_result['successful']}/{batch_result['total_requests']} successful"
)

print("\nDatabase Integration Pattern:")
db_processor = create_database_integration_pattern()
db_result = db_processor.process_table(
    "customers", "postgresql://localhost/mydb", chunk_size=75
)
print(
    f"  Database processing: {db_result['status']}, {db_result['chunks_processed']} chunks"
)

# %%
print("\n" + "📊 Performance Monitoring and Metrics:")


class PIIProcessingMonitor:
    """Monitor PII processing performance and generate metrics"""

    def __init__(self):
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_records_processed": 0,
            "total_processing_time": 0,
            "average_coverage": 0,
            "peak_throughput": 0,
            "error_types": {},
            "processing_history": [],
        }

    def record_processing(
        self, record_count, processing_time, coverage, success=True, error_type=None
    ):
        """Record a processing operation"""
        self.metrics["total_requests"] += 1

        if success:
            self.metrics["successful_requests"] += 1
            self.metrics["total_records_processed"] += record_count
            self.metrics["total_processing_time"] += processing_time

            # Update average coverage
            current_avg = self.metrics["average_coverage"]
            total_successful = self.metrics["successful_requests"]
            self.metrics["average_coverage"] = (
                current_avg * (total_successful - 1) + coverage
            ) / total_successful

            # Update peak throughput
            throughput = record_count / processing_time if processing_time > 0 else 0
            self.metrics["peak_throughput"] = max(
                self.metrics["peak_throughput"], throughput
            )

        else:
            self.metrics["failed_requests"] += 1
            if error_type:
                self.metrics["error_types"][error_type] = (
                    self.metrics["error_types"].get(error_type, 0) + 1
                )

        # Record in history
        self.metrics["processing_history"].append(
            {
                "timestamp": datetime.now(),
                "record_count": record_count,
                "processing_time": processing_time,
                "coverage": coverage if success else 0,
                "success": success,
                "error_type": error_type,
            }
        )

    def get_performance_report(self):
        """Generate a comprehensive performance report"""
        total_requests = self.metrics["total_requests"]

        if total_requests == 0:
            return "No processing operations recorded"

        success_rate = self.metrics["successful_requests"] / total_requests
        avg_processing_time = (
            self.metrics["total_processing_time"] / self.metrics["successful_requests"]
            if self.metrics["successful_requests"] > 0
            else 0
        )

        report = f"""
PII Processing Performance Report
================================

Overall Statistics:
- Total Requests: {total_requests:,}
- Success Rate: {success_rate:.1%}
- Total Records Processed: {self.metrics["total_records_processed"]:,}
- Average Coverage: {self.metrics["average_coverage"]:.1%}

Performance Metrics:
- Average Processing Time: {avg_processing_time:.3f}s
- Peak Throughput: {self.metrics["peak_throughput"]:.1f} records/sec
- Total Processing Time: {self.metrics["total_processing_time"]:.3f}s

Error Analysis:
- Failed Requests: {self.metrics["failed_requests"]}
- Error Types: {dict(self.metrics["error_types"])}

Recent Performance Trend:
"""

        # Add recent performance trend
        recent_history = self.metrics["processing_history"][-10:]  # Last 10 operations
        if recent_history:
            avg_recent_coverage = sum(h["coverage"] for h in recent_history) / len(
                recent_history
            )
            avg_recent_time = sum(h["processing_time"] for h in recent_history) / len(
                recent_history
            )
            report += f"- Recent Average Coverage: {avg_recent_coverage:.1%}\n"
            report += f"- Recent Average Time: {avg_recent_time:.3f}s\n"

        return report


# Demonstrate monitoring
monitor = PIIProcessingMonitor()

# Simulate various processing operations
test_operations = [
    (100, 0.5, 0.95, True, None),  # Successful operation
    (250, 1.2, 0.88, True, None),  # Successful operation
    (50, 0.3, 0.92, True, None),  # Successful operation
    (0, 0.1, 0, False, "empty_data"),  # Failed operation
    (500, 2.1, 0.97, True, None),  # Successful operation
    (75, 0.4, 0.85, True, None),  # Successful operation
    (200, 0.8, 0, False, "timeout"),  # Failed operation
    (150, 0.7, 0.91, True, None),  # Successful operation
]

print("Recording processing operations...")
for record_count, proc_time, coverage, success, error_type in test_operations:
    monitor.record_processing(record_count, proc_time, coverage, success, error_type)

# Generate performance report
performance_report = monitor.get_performance_report()
print(performance_report)

print("\n🚀 Production Checklist:")
print("✓ Error handling and logging implemented")
print("✓ Environment-specific configurations")
print("✓ Performance monitoring and optimization")
print("✓ Edge cases and data quality issues handled")
print("✓ CLI automation and scripting support")
print("✓ Integration patterns for common frameworks")
print("✓ Multi-format file processing capabilities")
print("✓ Streaming data processing support")
print("✓ Advanced integration patterns (Kafka, REST API, Database)")
print("✓ Comprehensive performance monitoring and metrics")
