"""Unit tests for Foundry harness and invariant generators."""

from pathlib import Path

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

    def test_invariant_with_source_path(self, tmp_path):
        from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests

        source = "contract Vault { uint256 public totalAssets; function totalSupply() public view returns (uint256) {} }"
        result = generate_invariant_tests(
            "Vault", source, tmp_path, source_path="src/vaults/Vault.sol"
        )

        content = result.read_text()
        assert 'import "src/vaults/Vault.sol"' in content

    def test_invariant_with_constructor_abi(self, tmp_path):
        from contract_audit.analyzers.foundry.invariant_generator import generate_invariant_tests

        source = "contract Token { mapping(address => uint256) public balanceOf; uint256 public totalSupply; }"
        ctor_abi = [{"type": "address", "name": "_token"}, {"type": "uint256", "name": "_amount"}]
        result = generate_invariant_tests(
            "Token", source, tmp_path, constructor_abi=ctor_abi
        )

        content = result.read_text()
        # Should use MockERC20 for the token address arg
        assert "MockERC20" in content
        # Should pass args to constructor
        assert "new Token(" in content
        assert "address(mockToken0)" in content


class TestHarnessWithConstructorArgs:
    def test_harness_no_constructor_uses_simple_new(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        result = generate_fuzz_harness("Simple", [], tmp_path)
        content = result.read_text()
        assert "target = new Simple();" in content

    def test_harness_with_token_constructor_generates_mock(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "address", "name": "_token"}]
        result = generate_fuzz_harness("Vault", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        assert "MockERC20" in content
        assert "address(mockToken0)" in content

    def test_harness_with_oracle_constructor_generates_mock(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "address", "name": "_priceFeed"}]
        result = generate_fuzz_harness("PriceConsumer", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        assert "MockOracle" in content
        assert "address(mockOracle0)" in content

    def test_harness_generic_address_uses_literal(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "address", "name": "_registry"}]
        result = generate_fuzz_harness("Proxy", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        # Generic address (no token/oracle hint) → address(N) literal
        assert "address(1)" in content
        assert "MockERC20" not in content
        assert "MockOracle" not in content

    def test_harness_uint_with_time_hint(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "uint256", "name": "_lockDelay"}]
        result = generate_fuzz_harness("Locker", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        assert "new Locker(3600)" in content

    def test_harness_uint_with_amount_hint(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "uint256", "name": "_totalSupply"}]
        result = generate_fuzz_harness("Token", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        assert "1_000_000e18" in content

    def test_harness_with_source_path(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        result = generate_fuzz_harness(
            "Vault", [], tmp_path, source_path="src/vaults/Vault.sol"
        )
        content = result.read_text()
        assert 'import "src/vaults/Vault.sol"' in content

    def test_dynamic_array_constructor_arg(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "address[]", "name": "_owners"}]
        result = generate_fuzz_harness("MultiSig", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        assert "new address[](0)" in content

    def test_fixed_array_constructor_arg(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "address[3]", "name": "_signers"}]
        result = generate_fuzz_harness("MultiSig", [], tmp_path, constructor_abi=ctor_abi)
        content = result.read_text()
        assert "[address(0), address(0), address(0)]" in content

    def test_tuple_constructor_arg(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_fuzz_harness

        ctor_abi = [{"type": "(address,uint256)", "name": "_config"}]
        result = generate_fuzz_harness("Vault", [], tmp_path, constructor_abi=ctor_abi)
        assert result != Path("")
        content = result.read_text()
        assert "(address(1), 100)" in content

    def test_targeted_harness_with_constructor_and_source_path(self, tmp_path):
        from contract_audit.analyzers.foundry.harness_generator import generate_targeted_harness
        from contract_audit.core.models import (
            Confidence,
            Finding,
            FindingCategory,
            Severity,
            SourceLocation,
        )

        finding = Finding(
            title="Reentrancy in withdraw",
            description="CEI violation",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.REENTRANCY,
            source="detector",
            detector_name="reentrancy",
            locations=[SourceLocation(file="src/Vault.sol", start_line=10, end_line=20,
                                      function="withdraw", contract="Vault")],
        )
        ctor_abi = [{"type": "address", "name": "_asset"}]
        result = generate_targeted_harness(
            "Vault", finding, "contract Vault {}", tmp_path,
            source_path="src/Vault.sol",
            constructor_abi=ctor_abi,
        )
        content = result.read_text()
        assert 'import "src/Vault.sol"' in content
        assert "MockERC20" in content
        assert "address(mockToken0)" in content
