import pytest
from contract_audit.core.models import AuditContext, Severity, Confidence
from contract_audit.detectors.reentrancy_detector import ReentrancyDetector
from contract_audit.detectors.oracle_detector import OracleDetector
from contract_audit.detectors.frontrun_detector import FrontrunDetector
from contract_audit.detectors.integer_detector import IntegerDetector


# Mock AST builder utilities
def create_mock_ast_node(node_type, **kwargs):
    node = {"nodeType": node_type, "id": kwargs.get("id", 1), "src": kwargs.get("src", "0:0:0")}
    for k, v in kwargs.items():
        node[k] = v
    return node


@pytest.mark.asyncio
async def test_reentrancy_detector_cei_ast():
    """Verify that AST-based CEI analysis identifies violations correctly based on node sequences."""
    # Source representing a CEI violation: transfer occurs, then state balance updated
    source = """
    contract Target {
        mapping(address => uint) balances;
        function withdraw(uint amount) public {
            msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    
    # Constructing a minimal mock AST tree
    # Contract definition containing balance state variable and withdraw function
    contract_node = create_mock_ast_node(
        "ContractDefinition",
        name="Target",
        nodes=[
            create_mock_ast_node("VariableDeclaration", name="balances", stateVariable=True),
            create_mock_ast_node(
                "FunctionDefinition",
                name="withdraw",
                body=create_mock_ast_node(
                    "Block",
                    nodes=[
                        # Call statement: msg.sender.call (offset 50)
                        create_mock_ast_node(
                            "ExpressionStatement",
                            expression=create_mock_ast_node(
                                "FunctionCall",
                                id=10,
                                src="50:20:0",
                                expression=create_mock_ast_node("MemberAccess", memberName="call"),
                                kind="functionCall"
                            )
                        ),
                        # Assignment: balances[msg.sender] -= amount (offset 100)
                        create_mock_ast_node(
                            "ExpressionStatement",
                            expression=create_mock_ast_node(
                                "Assignment",
                                id=11,
                                src="100:20:0",
                                leftHandSide=create_mock_ast_node("Identifier", name="balances"),
                                operator="-="
                            )
                        )
                    ]
                )
            )
        ]
    )

    ast_tree = {"nodeType": "SourceUnit", "nodes": [contract_node]}
    context = AuditContext(project_path=".")
    context.contract_sources = {"Target.sol": source}
    context.ast_trees = {"Target.sol": ast_tree}

    detector = ReentrancyDetector()
    findings = await detector.detect(context)

    # Filter for AST CEI findings
    cei_findings = [f for f in findings if "CEI Violation" in f.title]
    assert len(cei_findings) == 1
    assert cei_findings[0].severity == Severity.CRITICAL
    assert cei_findings[0].metadata["variable"] == "balances"


@pytest.mark.asyncio
async def test_oracle_detector_staleness_ast():
    """Verify that OracleDetector detects missing staleness validation on latestRoundData values."""
    source_unsafe = """
    contract PriceOracle {
        function getPrice() public returns (int256) {
            (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
            return price;
        }
    }
    """
    
    # Constructing a mock AST for unsafe oracle retrieve (no validation checks)
    call_node = create_mock_ast_node(
        "FunctionCall",
        id=20,
        src="80:30:0",
        expression=create_mock_ast_node("MemberAccess", memberName="latestRoundData")
    )
    
    contract_node = create_mock_ast_node(
        "ContractDefinition",
        name="PriceOracle",
        nodes=[
            create_mock_ast_node(
                "FunctionDefinition",
                name="getPrice",
                body=create_mock_ast_node(
                    "Block",
                    nodes=[
                        # Tuple binding statement allocating updatedAt at index 3
                        create_mock_ast_node(
                            "VariableDeclarationStatement",
                            initialValue=call_node,
                            declarations=[
                                None,
                                create_mock_ast_node("VariableDeclaration", name="price"),
                                None,
                                create_mock_ast_node("VariableDeclaration", name="updatedAt"),
                                None
                            ]
                        )
                    ]
                )
            )
        ]
    )

    ast_tree = {"nodeType": "SourceUnit", "nodes": [contract_node]}
    context = AuditContext(project_path=".")
    context.contract_sources = {"PriceOracle.sol": source_unsafe}
    context.ast_trees = {"PriceOracle.sol": ast_tree}

    detector = OracleDetector()
    findings = await detector.detect(context)

    staleness_findings = [f for f in findings if "Missing Staleness Check" in f.title]
    assert len(staleness_findings) == 1
    assert staleness_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_frontrun_detector_slippage_ast():
    """Verify that FrontrunDetector flags swap functions having unused slippage parameters."""
    source = """
    contract Trader {
        function swap(uint amountOutMin) public {
            // Unused slippage parameter
        }
    }
    """
    
    contract_node = create_mock_ast_node(
        "ContractDefinition",
        name="Trader",
        nodes=[
            create_mock_ast_node(
                "FunctionDefinition",
                name="swap",
                parameters=create_mock_ast_node(
                    "ParameterList",
                    parameters=[
                        create_mock_ast_node("VariableDeclaration", name="amountOutMin")
                    ]
                ),
                body=create_mock_ast_node("Block", nodes=[]) # Empty body, meaning amountOutMin is unused
            )
        ]
    )

    ast_tree = {"nodeType": "SourceUnit", "nodes": [contract_node]}
    context = AuditContext(project_path=".")
    context.contract_sources = {"Trader.sol": source}
    context.ast_trees = {"Trader.sol": ast_tree}

    detector = FrontrunDetector()
    findings = await detector.detect(context)

    unused_findings = [f for f in findings if "Unused Slippage Parameter" in f.title]
    assert len(unused_findings) == 1
    assert unused_findings[0].severity == Severity.HIGH
    assert "amountOutMin" in unused_findings[0].metadata["unused_parameters"]


@pytest.mark.asyncio
async def test_integer_detector_pragma_branch():
    """Verify that IntegerDetector behaves differently depending on solidity pragma compiler version."""
    source_pre_080 = """
    pragma solidity 0.7.6;
    contract UnsafeArithmetic {
        function add(uint a, uint b) public returns (uint) {
            return a + b; // vulnerable pre-0.8.0 without SafeMath
        }
    }
    """

    source_post_080 = """
    pragma solidity 0.8.19;
    contract SafeArithmetic {
        function add(uint a, uint b) public returns (uint) {
            return a + b; // safe in 0.8.0+
        }
    }
    """

    detector = IntegerDetector()

    # Case 1: Pre-0.8.0 should trigger missing SafeMath warning
    context_pre = AuditContext(project_path=".")
    context_pre.contract_sources = {"Unsafe.sol": source_pre_080}
    findings_pre = await detector.detect(context_pre)
    assert any("Missing SafeMath" in f.title for f in findings_pre)

    # Case 2: Post-0.8.0 should suppress SafeMath warning
    context_post = AuditContext(project_path=".")
    context_post.contract_sources = {"Safe.sol": source_post_080}
    findings_post = await detector.detect(context_post)
    assert not any("Missing SafeMath" in f.title for f in findings_post)
