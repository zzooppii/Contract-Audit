import pytest
from contract_audit.core.models import AuditContext, Severity, Confidence
from contract_audit.detectors.cross_contract_detector import CrossContractDetector


@pytest.mark.asyncio
async def test_cross_contract_read_only_reentrancy_detection():
    """Verify that CrossContractDetector identifies read-only reentrancy vulnerabilities across contracts."""
    # A queries B's getPrice() which is a view function
    source_a = """
    contract Lending {
        Pool public pool;
        function borrow() public {
            uint256 price = pool.getPrice();
            // action based on price
        }
    }
    """

    # B has updatePrice() which does call then state update (CEI violation)
    # and getPrice() which reads that state variable (price)
    source_b = """
    contract Pool {
        uint256 public price;
        function getPrice() public view returns (uint256) {
            return price;
        }
        function updatePrice(address target) public {
            target.call(""); // External call
            price = 200; // State variable update after call (CEI violation)
        }
    }
    """

    # Mock AST maps the vulnerable assignment in Pool.updatePrice
    # updatePrice (offset 150) -> call (offset 180) -> price assignment (offset 220)
    ast_b = {
        "nodeType": "SourceUnit",
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "name": "Pool",
                "nodes": [
                    {
                        "nodeType": "VariableDeclaration",
                        "name": "price"
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "name": "getPrice",
                        "stateMutability": "view"
                    },
                    {
                        "nodeType": "FunctionDefinition",
                        "name": "updatePrice",
                        "stateMutability": "nonpayable",
                        "nodes": [
                            {
                                "nodeType": "ExpressionStatement",
                                "expression": {
                                    "nodeType": "FunctionCall",
                                    "src": "180:10:0",
                                    "expression": {
                                        "nodeType": "MemberAccess",
                                        "memberName": "call"
                                    }
                                }
                            },
                            {
                                "nodeType": "ExpressionStatement",
                                "expression": {
                                    "nodeType": "Assignment",
                                    "src": "220:10:0",
                                    "leftHandSide": {
                                        "nodeType": "Identifier",
                                        "name": "price",
                                        "src": "220:5:0"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }

    # Set up mock CallGraph mapping
    call_graph = {
        "Lending": [("Pool", "getPrice")]
    }

    context = AuditContext(project_path=".")
    context.contract_sources = {
        "Lending.sol": source_a,
        "Pool.sol": source_b
    }
    context.ast_trees = {
        "Pool.sol": ast_b
    }
    context.call_graph = call_graph
    # Set other metadata to satisfy detect prerequisites
    context.import_graph = {}
    context.inheritance_map = {"Lending": [], "Pool": []}

    detector = CrossContractDetector()
    findings = await detector.detect(context)

    # Filter for read-only reentrancy findings
    ro_findings = [f for f in findings if "Cross-Contract Read-Only Reentrancy Risk" in f.title]
    assert len(ro_findings) == 1
    assert ro_findings[0].severity == Severity.HIGH
    assert ro_findings[0].metadata["vulnerable_contract"] == "Pool"
    assert ro_findings[0].metadata["view_function"] == "getPrice"
    assert ro_findings[0].metadata["variable"] == "price"
