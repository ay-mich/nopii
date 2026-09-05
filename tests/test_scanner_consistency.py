"""Regression checks for shared detection and SDK confidence handling."""

from types import SimpleNamespace

import pandas as pd
import pytest

from nopii.core.models import Policy, PolicyException, Rule
from nopii.core.scanner import Scanner
from nopii.detectors.base import BaseDetector
from nopii.sdk.scanner import SDKScanner


class SampleDetector(BaseDetector):
    def __init__(self, object_matches=False):
        super().__init__("sample")
        self.object_matches = object_matches
        self.contexts = []

    def detect(self, text, context=None):
        self.contexts.append(context)
        matches = []
        for token, confidence in [("low", 0.0), ("high", 0.9)]:
            start = text.find(token)
            if start < 0:
                continue
            end = start + len(token)
            if self.object_matches:
                matches.append(
                    SimpleNamespace(
                        value=token,
                        span=(start, end),
                        confidence=confidence,
                        evidence="custom evidence",
                    )
                )
            else:
                matches.append((start, end, confidence))
        return matches


@pytest.fixture
def scanner():
    scanner = Scanner(Policy(thresholds={"min_confidence": 0.8}))
    for name in scanner.detector_registry.list_detectors():
        scanner.detector_registry.unregister(name)
    scanner.detector_registry.register(SampleDetector())
    return scanner


@pytest.mark.parametrize("object_matches", [False, True])
@pytest.mark.parametrize("input_format", ["text", "dict", "dataframe", "txt", "csv"])
def test_scan_paths_preserve_matches_and_zero_threshold(
    scanner, tmp_path, input_format, object_matches
):
    detector = SampleDetector(object_matches)
    scanner.detector_registry.register(detector)
    text = "low high"
    expected_column = "text"
    if input_format == "text":
        findings = scanner.scan_text(text, 0.0)
    elif input_format == "dict":
        findings = scanner.scan_dict({"message": text}, 0.0)
        expected_column = "message"
    elif input_format == "dataframe":
        findings = scanner.scan_dataframe(
            pd.DataFrame({"message": [text]}, index=[42]),
            confidence_threshold=0.0,
        ).findings
        expected_column = "message"
    else:
        path = tmp_path / f"sample.{input_format}"
        path.write_text(
            f"message\n{text}\n" if input_format == "csv" else f"{text}\n",
            encoding="utf-8",
        )
        result = scanner.scan_file(path, 0.0)
        findings = result.findings
        expected_column = "message" if input_format == "csv" else "line"
        assert (result.total_rows, result.total_columns) == (1, 1)
        assert result.scan_metadata["confidence_threshold"] == 0.0

    assert [finding.value for finding in findings] == ["low", "high"]
    assert [finding.span for finding in findings] == [(0, 3), (4, 8)]
    assert all(f.column == expected_column and f.row_index == 0 for f in findings)
    if object_matches:
        assert all(f.evidence == "custom evidence" for f in findings)
    expected_context = (
        {"column_name": "message"} if input_format in {"dataframe", "csv"} else None
    )
    assert detector.contexts == [expected_context]


def test_default_threshold_and_column_override(scanner):
    assert [f.value for f in scanner.scan_text("low high")] == ["high"]
    scanner.policy.rules = [Rule(columns=["message"], override_confidence=0.0)]
    result = scanner.scan_dataframe(pd.DataFrame({"message": ["low high"]}))
    assert [f.value for f in result.findings] == ["low", "high"]


@pytest.mark.parametrize("threshold,expected", [(0.0, ["low", "high"]), (1.0, [])])
def test_sdk_threshold_applies_before_detection_and_reporting(
    scanner, threshold, expected
):
    sdk = SDKScanner(scanner)
    assert [f["value"] for f in sdk.scan_text("low high", threshold)] == expected
    assert [
        f["value"] for f in sdk.scan_dictionary({"message": "low high"}, threshold)
    ] == expected
    result = sdk.scan_dataframe(
        pd.DataFrame({"message": ["low high"]}), confidence_threshold=threshold
    )
    assert [f.value for f in result.findings] == expected
    assert result.scan_metadata["confidence_threshold"] == threshold
    assert result.coverage_score == (0.0 if expected else 1.0)


@pytest.mark.parametrize("allowed", [False, True])
def test_coverage_consistent_across_result_formats(scanner, tmp_path, allowed):
    scanner.policy.rules = [Rule(columns=["declared"])]
    if allowed:
        scanner.policy.exceptions = [
            PolicyException(dataset="sample", allow_types=["sample"])
        ]
    path = tmp_path / "sample.txt"
    path.write_text("high", encoding="utf-8")
    results = [
        scanner.scan_text_result("high", "sample"),
        scanner.scan_dataframe(pd.DataFrame({"message": ["high"]}), "sample"),
        scanner.scan_file(path),
    ]
    assert [r.coverage_score for r in results] == [1.0 if allowed else 0.5] * 3
