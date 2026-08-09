from pathlib import Path
from contract_audit.core.models import Finding, FindingCategory, Severity, Confidence
from contract_audit.analyzers.foundry.harness_generator import (
    generate_fuzz_harness,
    generate_targeted_harness,
    _extract_pragma,
    _is_pre_080,
)
from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests


def test_pragma_extraction_helpers():
    """Verify that pragma extraction and pre-0.8.0 detection helpers work correctly."""
    source_076 = "pragma solidity 0.7.6;\ncontract Target {}"
    source_080 = "pragma solidity ^0.8.0;\ncontract Target {}"
    source_none = "contract Target {}"

    assert _extract_pragma(source_076) == "0.7.6"
    assert _extract_pragma(source_080) == "^0.8.0"
    assert _extract_pragma(source_none) == "^0.8.0"

    assert _is_pre_080("0.7.6") is True
    assert _is_pre_080("^0.8.0") is False
    assert _is_pre_080("0.8.19") is False


def test_targeted_harness_generation_pragma_pre_080(tmp_path):
    """Verify that generate_targeted_harness replaces pragma and type limits on pre-0.8.0 targets."""
    source = """
    pragma solidity 0.7.6;
    contract Trader {
        function swap(uint256 amount) public {
            // target logic
        }
    }
    """
    finding = Finding(
        title="Targeted Finding",
        description="test description",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detector_name="test_detector",
        category=FindingCategory.ARITHMETIC,
        source="test_detector",
        locations=[]
    )

    harness_path = generate_targeted_harness(
        contract_name="Trader",
        finding=finding,
        source=source,
        output_dir=tmp_path,
        source_path="src/Trader.sol"
    )

    assert harness_path.exists()
    content = harness_path.read_text()

    # Should contain target pragma solidity
    assert "pragma solidity 0.7.6;" in content
    # Should replace type(uint256).max with uint256(-1)
    assert "uint256(-1)" in content
    assert "type(uint256).max" not in content


def test_invariant_harness_generation_pragma_pre_080(tmp_path):
    """Verify that generate_invariant_tests replaces pragma and type limits on pre-0.8.0 targets."""
    # Source representing token structure to trigger erc20_supply invariant (containing type(uint128).max)
    source = """
    pragma solidity ^0.7.0;
    contract Token {
        uint256 public totalSupply;
        mapping(address => uint256) public balanceOf;
    }
    """

    harness_path = generate_invariant_tests(
        contract_name="Token",
        source=source,
        output_dir=tmp_path,
        source_path="src/Token.sol"
    )

    assert harness_path.exists()
    content = harness_path.read_text()

    # Should contain target pragma solidity
    assert "pragma solidity ^0.7.0;" in content
    # Should replace type(uint128).max with uint128(-1)
    assert "uint128(-1)" in content
    assert "type(uint128).max" not in content


def test_harness_generation_pragma_post_080(tmp_path):
    """Verify that modern solidity targets keep modern syntax intact."""
    source = """
    pragma solidity 0.8.19;
    contract Trader {
        function swap(uint256 amount) public {}
    }
    """
    finding = Finding(
        title="Targeted Finding",
        description="test description",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        detector_name="test_detector",
        category=FindingCategory.ARITHMETIC,
        source="test_detector",
        locations=[]
    )

    harness_path = generate_targeted_harness(
        contract_name="Trader",
        finding=finding,
        source=source,
        output_dir=tmp_path,
        source_path="src/Trader.sol"
    )

    assert harness_path.exists()
    content = harness_path.read_text()

    # Should preserve pragma solidity 0.8.19
    assert "pragma solidity 0.8.19;" in content
    # Should preserve type(uint256).max
    assert "type(uint256).max" in content
    assert "uint256(-1)" not in content
