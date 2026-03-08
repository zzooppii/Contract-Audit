"""Unit tests for Foundry harness and invariant generators."""


from contract_audit.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)


class TestTargetedHarnessGenerator:
    def test_generates_reentrancy_harness(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness

        finding = Finding(
            title="CEI Violation in withdraw()",
            description="State updated after external call",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.REENTRANCY,
            source="reentrancy_detector",
            detector_name="cei-violation",
            locations=[
                SourceLocation(
                    file="Vault.sol",
                    start_line=10,
                    end_line=20,
                    function="withdraw",
                    contract="Vault",
                )
            ],
        )

        result = generate_targeted_harness(
            "Vault", finding, "contract Vault {}", tmp_path
        )

        assert result.exists()
        content = result.read_text()
        assert "reentrancy" in content.lower()
        assert "Vault" in content
        assert "forge-std/Test.sol" in content

    def test_generates_arithmetic_harness(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness

        finding = Finding(
            title="Unchecked overflow",
            description="Arithmetic overflow",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.ARITHMETIC,
            source="integer_detector",
            detector_name="unchecked-overflow",
            locations=[
                SourceLocation(
                    file="Math.sol",
                    start_line=5,
                    end_line=10,
                    function="add",
                    contract="Math",
                )
            ],
        )

        result = generate_targeted_harness(
            "Math", finding, "contract Math {}", tmp_path
        )

        assert result.exists()
        content = result.read_text()
        assert "arithmetic" in content.lower()
        assert "type(uint256).max" in content

    def test_generates_access_control_harness(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness

        finding = Finding(
            title="Missing access control",
            description="No modifier on admin function",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.ACCESS_CONTROL,
            source="access_control_detector",
            detector_name="missing-access-control",
            locations=[
                SourceLocation(
                    file="Admin.sol",
                    start_line=5,
                    end_line=10,
                    function="setOwner",
                    contract="Admin",
                )
            ],
        )

        result = generate_targeted_harness(
            "Admin", finding, "contract Admin {}", tmp_path
        )

        assert result.exists()
        content = result.read_text()
        assert "unauthorized" in content.lower()


class TestInvariantGenerator:
    def test_generates_erc20_invariants(self, tmp_path):
        from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests

        source = """
contract Token {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function transfer(address to, uint256 amount) external {}
}
"""
        result = generate_invariant_tests("Token", source, tmp_path)

        assert result.exists()
        content = result.read_text()
        assert "invariant" in content.lower()
        assert "totalSupply" in content

    def test_generates_vault_invariants(self, tmp_path):
        from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests

        source = """
contract Vault {
    uint256 public totalAssets;
    function totalSupply() public view returns (uint256) {}
    function deposit(uint256 assets) external returns (uint256 shares) {}
}
"""
        result = generate_invariant_tests("Vault", source, tmp_path)

        assert result.exists()
        content = result.read_text()
        assert "invariant" in content.lower()

    def test_generates_ownable_invariants(self, tmp_path):
        from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests

        source = """
contract Owned {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
}
"""
        result = generate_invariant_tests("Owned", source, tmp_path)

        assert result.exists()
        content = result.read_text()
        assert "owner" in content.lower()

    def test_generates_default_for_unknown(self, tmp_path):
        from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests

        source = "contract Simple { uint256 x; }"
        result = generate_invariant_tests("Simple", source, tmp_path)

        assert result.exists()
        content = result.read_text()
        assert "invariant" in content.lower()

    def test_detect_invariants(self):
        from contract_audit.analyzers.foundry.invariant_generator import detect_invariants

        source = """
contract Token {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;
    modifier onlyOwner() {}
}
"""
        result = detect_invariants(source)
        assert "erc20_supply" in result
        assert "ownable" in result
