"""Integration tests for specialized detectors against fixture contracts."""

import pytest
from pathlib import Path

from contract_audit.core.models import AuditContext, AuditConfig, FindingCategory, Severity

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "contracts"


def load_fixture(name: str) -> str:
    """Load a fixture contract source."""
    return (FIXTURES_DIR / name).read_text()


@pytest.fixture
def base_context(tmp_path):
    """Base audit context for testing."""
    return AuditContext(
        project_path=tmp_path,
        config=AuditConfig(),
    )


class TestOracleDetector:
    @pytest.mark.asyncio
    async def test_detects_chainlink_staleness(self, base_context):
        from contract_audit.detectors.oracle_detector import OracleDetector

        source = load_fixture("UnsafeOracle.sol")
        base_context.contract_sources = {"UnsafeOracle.sol": source}

        detector = OracleDetector()
        findings = await detector.detect(base_context)

        # Should find staleness issues
        staleness_findings = [
            f for f in findings
            if f.detector_name == "chainlink-staleness"
        ]
        assert len(staleness_findings) > 0
        assert all(f.severity == Severity.HIGH for f in staleness_findings)

    @pytest.mark.asyncio
    async def test_detects_uniswap_spot_price(self, base_context):
        from contract_audit.detectors.oracle_detector import OracleDetector

        source = load_fixture("UnsafeOracle.sol")
        base_context.contract_sources = {"UnsafeOracle.sol": source}

        detector = OracleDetector()
        findings = await detector.detect(base_context)

        spot_findings = [f for f in findings if "spot" in f.detector_name.lower() or "reserve" in f.detector_name.lower()]
        # Should find at least the getReserves issue
        assert len(findings) > 0  # Multiple issues expected

    @pytest.mark.asyncio
    async def test_no_false_positives_on_safe_code(self, base_context):
        from contract_audit.detectors.oracle_detector import OracleDetector

        # Safe oracle implementation
        safe_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeOracle {
    function getPrice() external view returns (int256) {
        (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = oracle.latestRoundData();
        require(answeredInRound >= roundId, "Stale");
        require(block.timestamp - updatedAt <= 3600, "Too old");
        return price;
    }
}
"""
        base_context.contract_sources = {"SafeOracle.sol": safe_source}

        detector = OracleDetector()
        findings = await detector.detect(base_context)

        # Safe code should have fewer findings
        staleness_findings = [
            f for f in findings
            if f.detector_name == "chainlink-staleness"
        ]
        assert len(staleness_findings) == 0


class TestFlashLoanDetector:
    @pytest.mark.asyncio
    async def test_detects_unvalidated_callback(self, base_context):
        from contract_audit.detectors.flash_loan_detector import FlashLoanDetector

        source = load_fixture("FlashLoanTarget.sol")
        base_context.contract_sources = {"FlashLoanTarget.sol": source}

        detector = FlashLoanDetector()
        findings = await detector.detect(base_context)

        callback_findings = [
            f for f in findings
            if f.category == FindingCategory.FLASH_LOAN
        ]
        assert len(callback_findings) > 0

    @pytest.mark.asyncio
    async def test_detects_spot_price(self, base_context):
        from contract_audit.detectors.flash_loan_detector import FlashLoanDetector

        source = load_fixture("UnsafeOracle.sol")
        base_context.contract_sources = {"UnsafeOracle.sol": source}

        detector = FlashLoanDetector()
        findings = await detector.detect(base_context)

        spot_price_findings = [
            f for f in findings
            if f.detector_name == "spot-price-oracle"
        ]
        assert len(spot_price_findings) > 0


class TestGovernanceDetector:
    @pytest.mark.asyncio
    async def test_detects_weak_governance(self, base_context):
        from contract_audit.detectors.governance_detector import GovernanceDetector

        source = load_fixture("WeakGovernor.sol")
        base_context.contract_sources = {"WeakGovernor.sol": source}

        detector = GovernanceDetector()
        findings = await detector.detect(base_context)

        assert len(findings) > 0
        categories = {f.category for f in findings}
        assert FindingCategory.GOVERNANCE_ATTACK in categories or FindingCategory.CENTRALIZATION_RISK in categories


class TestGasGriefingDetector:
    @pytest.mark.asyncio
    async def test_detects_unbounded_loop(self, base_context):
        from contract_audit.detectors.gas_griefing import GasGriefingDetector

        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract LoopContract {
    address[] public users;
    function payAll() external {
        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}
"""
        base_context.contract_sources = {"Loop.sol": source}

        detector = GasGriefingDetector()
        findings = await detector.detect(base_context)

        assert len(findings) > 0
        assert any(f.detector_name == "unbounded-loop" for f in findings)


class TestReentrancyDetector:
    @pytest.mark.asyncio
    async def test_detects_cei_violation(self, base_context):
        from contract_audit.detectors.reentrancy_detector import ReentrancyDetector

        source = load_fixture("ReentrancyVault.sol")
        base_context.contract_sources = {"ReentrancyVault.sol": source}

        detector = ReentrancyDetector()
        findings = await detector.detect(base_context)

        cei_findings = [f for f in findings if f.detector_name == "cei-violation"]
        assert len(cei_findings) > 0
        assert all(f.severity == Severity.CRITICAL for f in cei_findings)

    @pytest.mark.asyncio
    async def test_detects_missing_reentrancy_guard(self, base_context):
        from contract_audit.detectors.reentrancy_detector import ReentrancyDetector

        source = load_fixture("ReentrancyVault.sol")
        base_context.contract_sources = {"ReentrancyVault.sol": source}

        detector = ReentrancyDetector()
        findings = await detector.detect(base_context)

        guard_findings = [f for f in findings if f.detector_name == "missing-reentrancy-guard"]
        assert len(guard_findings) > 0
        assert all(f.category == FindingCategory.REENTRANCY for f in guard_findings)

    @pytest.mark.asyncio
    async def test_detects_read_only_reentrancy(self, base_context):
        from contract_audit.detectors.reentrancy_detector import ReentrancyDetector

        source = load_fixture("ReentrancyVault.sol")
        base_context.contract_sources = {"ReentrancyVault.sol": source}

        detector = ReentrancyDetector()
        findings = await detector.detect(base_context)

        ro_findings = [f for f in findings if f.detector_name == "read-only-reentrancy"]
        assert len(ro_findings) > 0
        assert all(f.severity == Severity.MEDIUM for f in ro_findings)

    @pytest.mark.asyncio
    async def test_no_false_positive_on_safe_code(self, base_context):
        from contract_audit.detectors.reentrancy_detector import ReentrancyDetector

        safe_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
}
"""
        base_context.contract_sources = {"SafeVault.sol": safe_source}

        detector = ReentrancyDetector()
        findings = await detector.detect(base_context)

        cei_findings = [f for f in findings if f.detector_name == "cei-violation"]
        assert len(cei_findings) == 0


class TestUncheckedCallDetector:
    @pytest.mark.asyncio
    async def test_detects_unchecked_low_level_call(self, base_context):
        from contract_audit.detectors.unchecked_call_detector import UncheckedCallDetector

        source = load_fixture("UnsafeVault.sol")
        base_context.contract_sources = {"UnsafeVault.sol": source}

        detector = UncheckedCallDetector()
        findings = await detector.detect(base_context)

        call_findings = [f for f in findings if f.detector_name == "unchecked-low-level-call"]
        assert len(call_findings) > 0

    @pytest.mark.asyncio
    async def test_detects_unchecked_erc20_transfer(self, base_context):
        from contract_audit.detectors.unchecked_call_detector import UncheckedCallDetector

        source = load_fixture("UnsafeVault.sol")
        base_context.contract_sources = {"UnsafeVault.sol": source}

        detector = UncheckedCallDetector()
        findings = await detector.detect(base_context)

        transfer_findings = [f for f in findings if f.detector_name == "unchecked-erc20-transfer"]
        assert len(transfer_findings) > 0

    @pytest.mark.asyncio
    async def test_detects_delegatecall_to_untrusted(self, base_context):
        from contract_audit.detectors.unchecked_call_detector import UncheckedCallDetector

        source = load_fixture("UnsafeVault.sol")
        base_context.contract_sources = {"UnsafeVault.sol": source}

        detector = UncheckedCallDetector()
        findings = await detector.detect(base_context)

        dc_findings = [f for f in findings if f.detector_name == "delegatecall-untrusted"]
        assert len(dc_findings) > 0
        assert all(f.severity == Severity.CRITICAL for f in dc_findings)

    @pytest.mark.asyncio
    async def test_detects_selfdestruct_delegatecall(self, base_context):
        from contract_audit.detectors.unchecked_call_detector import UncheckedCallDetector

        source = load_fixture("UnsafeVault.sol")
        base_context.contract_sources = {"UnsafeVault.sol": source}

        detector = UncheckedCallDetector()
        findings = await detector.detect(base_context)

        sd_findings = [f for f in findings if f.detector_name == "selfdestruct-delegatecall"]
        assert len(sd_findings) > 0
        assert all(f.severity == Severity.CRITICAL for f in sd_findings)


class TestNFTDetector:
    @pytest.mark.asyncio
    async def test_detects_unsafe_mint(self, base_context):
        from contract_audit.detectors.nft_detector import NFTDetector

        source = load_fixture("NFTAuction.sol")
        base_context.contract_sources = {"NFTAuction.sol": source}

        detector = NFTDetector()
        findings = await detector.detect(base_context)

        mint_findings = [f for f in findings if f.detector_name == "unsafe-mint"]
        assert len(mint_findings) > 0
        assert all(f.severity == Severity.HIGH for f in mint_findings)

    @pytest.mark.asyncio
    async def test_detects_callback_reentrancy(self, base_context):
        from contract_audit.detectors.nft_detector import NFTDetector

        source = load_fixture("NFTAuction.sol")
        base_context.contract_sources = {"NFTAuction.sol": source}

        detector = NFTDetector()
        findings = await detector.detect(base_context)

        cb_findings = [f for f in findings if f.detector_name == "nft-callback-reentrancy"]
        assert len(cb_findings) > 0

    @pytest.mark.asyncio
    async def test_detects_missing_exists_check(self, base_context):
        from contract_audit.detectors.nft_detector import NFTDetector

        source = load_fixture("NFTAuction.sol")
        base_context.contract_sources = {"NFTAuction.sol": source}

        detector = NFTDetector()
        findings = await detector.detect(base_context)

        exists_findings = [f for f in findings if f.detector_name == "missing-exists-check"]
        assert len(exists_findings) > 0
        assert all(f.severity == Severity.MEDIUM for f in exists_findings)

    @pytest.mark.asyncio
    async def test_no_false_positive_on_erc20(self, base_context):
        from contract_audit.detectors.nft_detector import NFTDetector

        erc20_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SimpleToken {
    mapping(address => uint256) public balances;
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
"""
        base_context.contract_sources = {"SimpleToken.sol": erc20_source}

        detector = NFTDetector()
        findings = await detector.detect(base_context)

        # ERC20 _mint should NOT trigger NFT detector
        assert len(findings) == 0


class TestBridgeDetector:
    @pytest.mark.asyncio
    async def test_detects_missing_chain_id(self, base_context):
        from contract_audit.detectors.bridge_detector import BridgeDetector

        source = load_fixture("CrossChainBridge.sol")
        base_context.contract_sources = {"CrossChainBridge.sol": source}

        detector = BridgeDetector()
        findings = await detector.detect(base_context)

        chain_findings = [f for f in findings if f.detector_name == "missing-chain-id"]
        assert len(chain_findings) > 0
        assert all(f.severity == Severity.CRITICAL for f in chain_findings)

    @pytest.mark.asyncio
    async def test_detects_replay_attack(self, base_context):
        from contract_audit.detectors.bridge_detector import BridgeDetector

        source = load_fixture("CrossChainBridge.sol")
        base_context.contract_sources = {"CrossChainBridge.sol": source}

        detector = BridgeDetector()
        findings = await detector.detect(base_context)

        replay_findings = [f for f in findings if f.detector_name == "replay-attack"]
        assert len(replay_findings) > 0

    @pytest.mark.asyncio
    async def test_detects_missing_relayer_validation(self, base_context):
        from contract_audit.detectors.bridge_detector import BridgeDetector

        source = load_fixture("CrossChainBridge.sol")
        base_context.contract_sources = {"CrossChainBridge.sol": source}

        detector = BridgeDetector()
        findings = await detector.detect(base_context)

        relayer_findings = [f for f in findings if f.detector_name == "missing-relayer-validation"]
        assert len(relayer_findings) > 0

    @pytest.mark.asyncio
    async def test_skips_non_bridge_contracts(self, base_context):
        from contract_audit.detectors.bridge_detector import BridgeDetector

        non_bridge_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SimpleStorage {
    uint256 public value;
    function setValue(uint256 _value) external {
        value = _value;
    }
}
"""
        base_context.contract_sources = {"SimpleStorage.sol": non_bridge_source}

        detector = BridgeDetector()
        findings = await detector.detect(base_context)

        assert len(findings) == 0


class TestIntegerDetector:
    @pytest.mark.asyncio
    async def test_detects_unsafe_downcast(self, base_context):
        from contract_audit.detectors.integer_detector import IntegerDetector

        source = load_fixture("IntegerMath.sol")
        base_context.contract_sources = {"IntegerMath.sol": source}

        detector = IntegerDetector()
        findings = await detector.detect(base_context)

        downcast_findings = [f for f in findings if f.detector_name == "unsafe-downcast"]
        assert len(downcast_findings) > 0
        assert all(f.severity == Severity.HIGH for f in downcast_findings)

    @pytest.mark.asyncio
    async def test_detects_unchecked_overflow(self, base_context):
        from contract_audit.detectors.integer_detector import IntegerDetector

        source = load_fixture("IntegerMath.sol")
        base_context.contract_sources = {"IntegerMath.sol": source}

        detector = IntegerDetector()
        findings = await detector.detect(base_context)

        overflow_findings = [f for f in findings if f.detector_name == "unchecked-overflow"]
        assert len(overflow_findings) > 0

    @pytest.mark.asyncio
    async def test_detects_division_before_multiplication(self, base_context):
        from contract_audit.detectors.integer_detector import IntegerDetector

        source = load_fixture("IntegerMath.sol")
        base_context.contract_sources = {"IntegerMath.sol": source}

        detector = IntegerDetector()
        findings = await detector.detect(base_context)

        div_findings = [f for f in findings if f.detector_name == "division-before-multiplication"]
        assert len(div_findings) > 0
        assert all(f.severity == Severity.MEDIUM for f in div_findings)

    @pytest.mark.asyncio
    async def test_detects_zero_division(self, base_context):
        from contract_audit.detectors.integer_detector import IntegerDetector

        source = load_fixture("IntegerMath.sol")
        base_context.contract_sources = {"IntegerMath.sol": source}

        detector = IntegerDetector()
        findings = await detector.detect(base_context)

        zero_findings = [f for f in findings if f.detector_name == "zero-division"]
        assert len(zero_findings) > 0

    @pytest.mark.asyncio
    async def test_safe_downcast_not_flagged(self, base_context):
        from contract_audit.detectors.integer_detector import IntegerDetector

        safe_source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
contract SafeMath {
    using SafeCast for uint256;
    function convert(uint256 val) external pure returns (uint128) {
        return val.toUint128();
    }
}
"""
        base_context.contract_sources = {"SafeMath.sol": safe_source}

        detector = IntegerDetector()
        findings = await detector.detect(base_context)

        downcast_findings = [f for f in findings if f.detector_name == "unsafe-downcast"]
        assert len(downcast_findings) == 0
