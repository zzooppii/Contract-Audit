"""Unit tests for Foundry result parser."""

from __future__ import annotations

from contract_audit.analyzers.foundry.result_parser import (
    _classify_failure,
    _extract_source_location,
    _format_counterexample,
    _failure_to_finding,
    parse_foundry_results,
)
from contract_audit.core.models import FindingCategory, Severity


class TestParseFoundryResults:
    def test_empty_output(self):
        assert parse_foundry_results({}) == []

    def test_non_dict_test_results_skipped(self):
        output = {"SomeTest.t.sol": "not a dict"}
        assert parse_foundry_results(output) == []

    def test_passing_tests_produce_no_findings(self):
        output = {
            "src/Vault.t.sol": {
                "test_results": {
                    "testFuzz_deposit": {"status": "Success"},
                    "testFuzz_withdraw": {"status": "Success"},
                }
            }
        }
        assert parse_foundry_results(output) == []

    def test_failing_test_produces_finding(self):
        output = {
            "src/Vault.t.sol": {
                "test_results": {
                    "testFuzz_withdraw": {
                        "status": "Failure",
                        "reason": "Assertion violated",
                    }
                }
            }
        }
        findings = parse_foundry_results(output)
        assert len(findings) == 1
        assert findings[0].source == "foundry"
        assert "testFuzz_withdraw" in findings[0].title

    def test_multiple_failures_produce_multiple_findings(self):
        output = {
            "src/Vault.t.sol": {
                "test_results": {
                    "test_a": {"status": "Failure", "reason": "revert"},
                    "test_b": {"status": "Success"},
                    "test_c": {"status": "Failure", "reason": "overflow"},
                }
            }
        }
        findings = parse_foundry_results(output)
        assert len(findings) == 2

    def test_counterexample_included_in_description(self):
        output = {
            "src/Math.t.sol": {
                "test_results": {
                    "testFuzz_add": {
                        "status": "Failure",
                        "reason": "overflow",
                        "counterexample": {"amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935"},
                    }
                }
            }
        }
        findings = parse_foundry_results(output)
        assert len(findings) == 1
        assert "Counterexample" in findings[0].description

    def test_decoded_logs_included_in_description(self):
        output = {
            "src/Vault.t.sol": {
                "test_results": {
                    "test_reentrancy": {
                        "status": "Failure",
                        "reason": "",
                        "decoded_logs": ["AttackCount: 2", "Balance drained"],
                    }
                }
            }
        }
        findings = parse_foundry_results(output)
        assert "Logs" in findings[0].description


class TestClassifyFailure:
    def test_invariant_test(self):
        cat, sev = _classify_failure("invariant_totalSupply", "")
        assert cat == FindingCategory.OTHER
        assert sev == Severity.HIGH

    def test_reentrancy_test(self):
        cat, sev = _classify_failure("test_reentrancy_withdraw", "")
        assert cat == FindingCategory.REENTRANCY
        assert sev == Severity.CRITICAL

    def test_overflow_in_reason(self):
        # Use a non-fuzz test name to avoid early return on "fuzz" check
        cat, sev = _classify_failure("test_add", "underflow detected")
        assert cat == FindingCategory.ARITHMETIC
        assert sev == Severity.HIGH

    def test_oracle_test(self):
        cat, sev = _classify_failure("test_oracle_manipulation", "")
        assert cat == FindingCategory.ORACLE_MANIPULATION
        assert sev == Severity.HIGH

    def test_flash_test(self):
        cat, sev = _classify_failure("test_flash_attack", "")
        assert cat == FindingCategory.FLASH_LOAN
        assert sev == Severity.HIGH

    def test_generic_fuzz_test(self):
        cat, sev = _classify_failure("testFuzz_transfer", "")
        assert cat == FindingCategory.OTHER
        assert sev == Severity.MEDIUM

    def test_unknown_defaults_to_medium(self):
        cat, sev = _classify_failure("test_something_weird", "")
        assert cat == FindingCategory.OTHER
        assert sev == Severity.MEDIUM


class TestExtractSourceLocation:
    def test_extracts_sol_line_from_reason(self):
        file_, line = _extract_source_location(
            "Assertion failed at src/Vault.sol:42", [], "fallback.t.sol"
        )
        assert file_ == "src/Vault.sol"
        assert line == 42

    def test_extracts_from_decoded_logs(self):
        file_, line = _extract_source_location(
            "", ["Error at contracts/Token.sol:99"], "fallback.t.sol"
        )
        assert file_ == "contracts/Token.sol"
        assert line == 99

    def test_reason_takes_priority_over_logs(self):
        file_, line = _extract_source_location(
            "src/A.sol:10 failed",
            ["src/B.sol:20 also failed"],
            "fallback.t.sol",
        )
        assert file_ == "src/A.sol"
        assert line == 10

    def test_fallback_when_no_location_found(self):
        file_, line = _extract_source_location("generic error", [], "my.t.sol")
        assert file_ == "my.t.sol"
        assert line == 1

    def test_empty_inputs_fallback(self):
        file_, line = _extract_source_location("", [], "fallback.t.sol")
        assert file_ == "fallback.t.sol"
        assert line == 1


class TestFormatCounterexample:
    def test_dict_counterexample(self):
        ce = {"amount": "100", "recipient": "0xdead"}
        result = _format_counterexample(ce)
        assert "amount" in result
        assert "100" in result

    def test_string_counterexample(self):
        result = _format_counterexample("Call(amount=999)")
        assert "999" in result

    def test_list_counterexample(self):
        result = _format_counterexample([1, 2, 3])
        assert result  # just ensure it doesn't crash
