"""Edge case tests: all 22 detectors must not crash on abnormal inputs."""

import importlib
import pytest

from contract_audit.core.models import AuditContext, AuditConfig


# All 22 detectors: (class_name, module_name)
ALL_DETECTORS = [
    ("ReentrancyDetector", "contract_audit.detectors.reentrancy_detector"),
    ("AccessControlDetector", "contract_audit.detectors.access_control_detector"),
    ("ERC20Detector", "contract_audit.detectors.erc20_detector"),
    ("UncheckedCallDetector", "contract_audit.detectors.unchecked_call_detector"),
    ("NFTDetector", "contract_audit.detectors.nft_detector"),
    ("BridgeDetector", "contract_audit.detectors.bridge_detector"),
    ("IntegerDetector", "contract_audit.detectors.integer_detector"),
    ("FrontrunDetector", "contract_audit.detectors.frontrun_detector"),
    ("InitializationDetector", "contract_audit.detectors.initialization_detector"),
    ("ERC4626Detector", "contract_audit.detectors.erc4626_detector"),
    ("SignatureDetector", "contract_audit.detectors.signature_detector"),
    ("RandomnessDetector", "contract_audit.detectors.randomness_detector"),
    ("MerkleDetector", "contract_audit.detectors.merkle_detector"),
    ("TimelockDetector", "contract_audit.detectors.timelock_detector"),
    ("GasGriefingDetector", "contract_audit.detectors.gas_griefing"),
    ("OracleDetector", "contract_audit.detectors.oracle_detector"),
    ("FlashLoanDetector", "contract_audit.detectors.flash_loan_detector"),
    ("GovernanceDetector", "contract_audit.detectors.governance_detector"),
    ("ProxyDetector", "contract_audit.detectors.proxy_detector"),
    ("StorageCollisionDetector", "contract_audit.detectors.storage_collision"),
    ("PragmaDetector", "contract_audit.detectors.pragma_detector"),
    ("CrossContractDetector", "contract_audit.detectors.cross_contract_detector"),
]

EDGE_CASES = {
    "empty_file": "",
    "comments_only": "// just a comment\n/* block */",
    "pragma_only": "pragma solidity ^0.8.0;",
    "interface_only": "interface IFoo { function bar() external; }",
    "abstract_only": "abstract contract Foo { function bar() virtual; }",
    "library_only": (
        "library SafeMath { "
        "function add(uint a, uint b) internal pure returns (uint) { return a + b; } }"
    ),
    "assembly_block": (
        "contract Foo { function bar() public { assembly { let x := 0 } } }"
    ),
    "unicode_identifiers": "contract Café { function résumé() public {} }",
    "deeply_nested": (
        "contract A { function f() public { if(true) { if(true) { if(true) { } } } } }"
    ),
    "single_line_contract": "contract X { }",
    "no_functions": "contract X { uint public x; mapping(address => uint) balances; }",
    "huge_function": "contract X { function f() public { " + "x = 1; " * 500 + "} }",
}


def _make_context(source: str, filename: str, tmp_path) -> AuditContext:
    """Build a minimal AuditContext with the given source."""
    return AuditContext(
        project_path=tmp_path,
        contract_sources={filename: source},
        config=AuditConfig(
            llm_enabled=False,
            slither_enabled=False,
            aderyn_enabled=False,
            foundry_fuzz_enabled=False,
            symbolic_enabled=False,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("detector_cls,module", ALL_DETECTORS, ids=[d[0] for d in ALL_DETECTORS])
@pytest.mark.parametrize("case_name,source", EDGE_CASES.items(), ids=EDGE_CASES.keys())
async def test_detector_edge_case(detector_cls, module, case_name, source, tmp_path):
    """Every detector must return a list (not crash) on edge case inputs."""
    mod = importlib.import_module(module)
    cls = getattr(mod, detector_cls)
    detector = cls()

    context = _make_context(source, f"EdgeCase_{case_name}.sol", tmp_path)
    findings = await detector.detect(context)

    assert isinstance(findings, list), (
        f"{detector_cls} returned {type(findings)} instead of list "
        f"for edge case '{case_name}'"
    )
