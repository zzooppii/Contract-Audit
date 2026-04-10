"""Generate Foundry fuzz test harnesses for audit targets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Inline mock contracts — emitted into harness files when needed
# ---------------------------------------------------------------------------

MOCK_ERC20 = """\
contract MockERC20 {
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}"""

MOCK_ORACLE = """\
contract MockOracle {
    int256 public price = 2000e8;

    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (1, price, block.timestamp, block.timestamp, 1);
    }

    function setPrice(int256 _price) external {
        price = _price;
    }
}"""

# Keyword hints used by _build_constructor_setup
_TOKEN_HINTS = {"token", "asset", "underlying", "weth", "usdc", "dai", "reward", "staking", "erc20"}
_ORACLE_HINTS = {"oracle", "feed", "price", "aggregator", "chainlink"}
_TIME_HINTS = {"time", "delay", "period", "duration", "lock", "expir"}
_AMOUNT_HINTS = {"amount", "supply", "total", "cap", "limit", "balance"}


def _build_constructor_setup(
    contract_name: str,
    constructor_inputs: list[dict[str, Any]] | None,
) -> tuple[str, str]:
    """Generate setUp() body and any required mock contract code.

    Args:
        contract_name: Solidity contract being tested
        constructor_inputs: ABI ``inputs`` list from the constructor entry,
            or ``None`` / empty list for zero-arg constructors.

    Returns:
        ``(mock_code, setup_body)`` where *mock_code* is emitted before the
        test contract in the file and *setup_body* replaces the contents of
        ``setUp()``.
    """
    if not constructor_inputs:
        return "", f"target = new {contract_name}();"

    mocks_needed: set[str] = set()
    setup_lines: list[str] = []
    ctor_args: list[str] = []
    mock_counter = 0

    for inp in constructor_inputs:
        type_ = inp.get("type", "")
        raw_name = inp.get("name", "")
        name_lower = raw_name.lower().lstrip("_")

        if type_ == "address":
            if any(h in name_lower for h in _TOKEN_HINTS):
                mocks_needed.add("erc20")
                var = f"mockToken{mock_counter}"
                setup_lines.append(f"MockERC20 {var} = new MockERC20();")
                setup_lines.append(f"{var}.mint(address(this), 1_000_000e18);")
                ctor_args.append(f"address({var})")
            elif any(h in name_lower for h in _ORACLE_HINTS):
                mocks_needed.add("oracle")
                var = f"mockOracle{mock_counter}"
                setup_lines.append(f"MockOracle {var} = new MockOracle();")
                ctor_args.append(f"address({var})")
            else:
                # Generic address — use a deterministic placeholder
                ctor_args.append(f"address({mock_counter + 1})")
            mock_counter += 1

        elif type_.startswith("uint") or type_.startswith("int"):
            if any(h in name_lower for h in _TIME_HINTS):
                ctor_args.append("3600")
            elif any(h in name_lower for h in _AMOUNT_HINTS):
                ctor_args.append("1_000_000e18")
            else:
                ctor_args.append("100")

        elif type_ == "bool":
            ctor_args.append("true")
        elif type_ == "bytes32":
            ctor_args.append("bytes32(0)")
        elif type_ in ("string",):
            ctor_args.append('""')
        elif type_ in ("bytes",):
            ctor_args.append('""')
        elif type_.endswith("[]"):
            # Dynamic array — pass empty array
            base_type = type_[:-2]
            ctor_args.append(f"new {base_type}[](0)")
        elif re.match(r'.+\[\d+\]$', type_):
            # Fixed-size array — cannot easily initialise inline; emit TODO comment
            ctor_args.append(f"/* TODO: {type_} */")
        elif type_.startswith("(") or "tuple" in type_:
            # Tuple / struct — cannot auto-generate; emit TODO comment
            ctor_args.append(f"/* TODO: {type_} */")
        else:
            # Unknown scalar — attempt cast-to-zero
            ctor_args.append(f"{type_}(0)")

    # Assemble mock code block (only include each mock once)
    mock_parts: list[str] = []
    if "erc20" in mocks_needed:
        mock_parts.append(MOCK_ERC20)
    if "oracle" in mocks_needed:
        mock_parts.append(MOCK_ORACLE)
    mock_code = "\n\n".join(mock_parts)

    setup_prefix = "\n        ".join(setup_lines)
    deploy = f"target = new {contract_name}({', '.join(ctor_args)});"
    setup_body = f"{setup_prefix}\n        {deploy}" if setup_prefix else deploy

    return mock_code, setup_body


# ---------------------------------------------------------------------------
# Generic ABI-based fuzz harness
# ---------------------------------------------------------------------------

def generate_fuzz_harness(
    contract_name: str,
    functions: list[dict[str, Any]],
    output_dir: Path,
    *,
    source_path: str | None = None,
    constructor_abi: list[dict[str, Any]] | None = None,
) -> Path:
    """Generate a Foundry fuzz test harness for a contract.

    Args:
        contract_name: Name of the contract to fuzz
        functions: List of function dicts with {name, inputs, stateMutability}
        output_dir: Directory to write the test file
        source_path: Relative path to the contract source (e.g. ``src/Vault.sol``).
            Used to build the Solidity import statement. Defaults to
            ``src/{contract_name}.sol``.
        constructor_abi: ABI ``inputs`` list for the constructor, used to
            generate mock deployments in ``setUp()``.

    Returns:
        Path to the generated test file
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    test_file = output_dir / f"Fuzz{contract_name}.t.sol"

    import_path = source_path if source_path else f"src/{contract_name}.sol"
    mock_code, setup_body = _build_constructor_setup(contract_name, constructor_abi)

    function_tests = []
    for fn in functions:
        if fn.get("stateMutability") in ("view", "pure"):
            continue
        fn_name = fn.get("name", "")
        if not fn_name or fn_name.startswith("_"):
            continue

        params = _build_params(fn.get("inputs", []))
        param_names = [p.split()[-1] for p in params] if params else []

        function_tests.append(f"""
    function testFuzz_{fn_name}({', '.join(params)}) public {{
        target.{fn_name}({', '.join(param_names)});
    }}""")

    mock_section = f"\n{mock_code}\n" if mock_code else ""

    content = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{import_path}";
{mock_section}
/// @title Fuzz test harness for {contract_name}
/// @notice Auto-generated by contract-audit
contract Fuzz{contract_name}Test is Test {{
    {contract_name} target;

    function setUp() public {{
        {setup_body}
    }}
{''.join(function_tests)}

    /// @notice Invariant: contract should still be deployed
    function invariant_contractExists() public {{
        assertTrue(address(target).code.length > 0, "Contract should still exist");
    }}
}}
"""
    test_file.write_text(content)
    return test_file


def _build_params(inputs: list[dict[str, Any]]) -> list[str]:
    """Build Solidity parameter declarations from ABI inputs."""
    params: list[str] = []
    for inp in inputs:
        type_ = _map_type(inp.get("type", "uint256"))
        name = inp.get("name", f"param{len(params)}")
        params.append(f"{type_} {name}")
    return params


def _map_type(solidity_type: str) -> str:
    """Map Solidity ABI types to fuzz-friendly types."""
    type_map = {
        "uint": "uint256",
        "int": "int256",
        "bool": "bool",
        "address": "address",
        "bytes": "bytes",
        "string": "string",
    }
    for prefix in type_map:
        if solidity_type.startswith(prefix):
            return solidity_type
    return solidity_type


def _extract_function_params(source: str, func_name: str) -> list[tuple[str, str]]:
    """Extract (type, name) pairs from a Solidity function signature in source.

    Returns list of (solidity_type, param_name) tuples. Falls back to empty
    list if the function signature cannot be found or parsed.
    """
    pattern = rf'function\s+{re.escape(func_name)}\s*\(([^)]*)\)'
    match = re.search(pattern, source)
    if not match:
        return []
    params_str = match.group(1).strip()
    if not params_str:
        return []

    result: list[tuple[str, str]] = []
    _DATA_LOCATION = {"memory", "calldata", "storage"}
    for idx, part in enumerate(params_str.split(",")):
        tokens = [t for t in part.strip().split() if t not in _DATA_LOCATION]
        if not tokens:
            continue
        if len(tokens) >= 2:
            type_ = " ".join(tokens[:-1])
            name = tokens[-1].lstrip("_") or f"param{idx}"
        else:
            type_ = tokens[0]
            name = f"param{idx}"
        result.append((type_, name))
    return result


# ---------------------------------------------------------------------------
# Finding-based targeted harness generation
# ---------------------------------------------------------------------------

def generate_targeted_harness(
    contract_name: str,
    finding: Any,
    source: str,
    output_dir: Path,
    *,
    source_path: str | None = None,
    constructor_abi: list[dict[str, Any]] | None = None,
) -> Path:
    """Generate a targeted fuzz test based on a specific finding.

    For reentrancy findings, generates a real attacker contract with a
    receive()/fallback() that re-enters the target function. For arithmetic
    and access-control findings, generates boundary-value and permission tests
    with function arguments inferred from the source code.

    Args:
        contract_name: Name of the vulnerable contract
        finding: Finding object with category and location
        source: Contract source code
        output_dir: Directory to write test file
        source_path: Relative path to the contract source file
            (e.g. ``src/vaults/Vault.sol``). Used for the Solidity import.
        constructor_abi: ABI ``inputs`` list for the constructor.

    Returns:
        Path to the generated test file
    """
    from ...core.models import FindingCategory

    output_dir.mkdir(parents=True, exist_ok=True)

    func_name = ""
    if finding.locations:
        func_name = finding.locations[0].function or ""

    safe_fn = re.sub(r'[^a-zA-Z0-9_]', '_', func_name) if func_name else "unknown"
    import_path = source_path if source_path else f"src/{contract_name}.sol"

    # Extract function parameters from source for argument generation
    params = _extract_function_params(source, func_name) if func_name else []
    param_decls = ", ".join(f"{t} {n}" for t, n in params)
    call_args = ", ".join(n for _, n in params)

    mock_code, setup_body = _build_constructor_setup(contract_name, constructor_abi)

    test_file = output_dir / f"Targeted_{contract_name}_{safe_fn}.t.sol"

    if finding.category in (FindingCategory.REENTRANCY,):
        content = _build_reentrancy_harness(
            contract_name, safe_fn, func_name, params,
            param_decls, call_args, finding, import_path, mock_code, setup_body,
        )
    elif finding.category in (FindingCategory.ARITHMETIC,):
        content = _build_arithmetic_harness(
            contract_name, safe_fn, func_name, params,
            param_decls, call_args, finding, import_path, mock_code, setup_body,
        )
    elif finding.category in (FindingCategory.ACCESS_CONTROL,):
        content = _build_access_control_harness(
            contract_name, safe_fn, func_name, params,
            param_decls, call_args, finding, import_path, mock_code, setup_body,
        )
    else:
        content = _build_reentrancy_harness(
            contract_name, safe_fn, func_name, params,
            param_decls, call_args, finding, import_path, mock_code, setup_body,
        )

    test_file.write_text(content)
    return test_file


def _build_reentrancy_harness(
    contract_name: str,
    safe_fn: str,
    func_name: str,
    params: list[tuple[str, str]],
    param_decls: str,
    call_args: str,
    finding: Any,
    import_path: str,
    mock_code: str,
    setup_body: str,
) -> str:
    """Generate a reentrancy test with a real attacker contract that re-enters."""
    stored_fields = "\n    ".join(f"{t} private _{n};" for t, n in params)
    store_args = "\n        ".join(f"_{n} = {n};" for _, n in params)
    stored_call_args = ", ".join(f"_{n}" for _, n in params)

    mock_section = f"\n{mock_code}\n" if mock_code else ""
    fn_or_default = func_name or "deposit"

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{import_path}";
{mock_section}
/// @notice Reentrancy attacker that re-enters {fn_or_default} via ETH callback
contract {contract_name}ReentrancyAttacker {{
    {contract_name} public target;
    uint256 public attackCount;
    bool private _attacking;
    {stored_fields}

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    function attack({param_decls}) external payable {{
        {store_args}
        target.{fn_or_default}({call_args});
    }}

    receive() external payable {{
        if (attackCount < 2 && !_attacking) {{
            attackCount++;
            _attacking = true;
            target.{fn_or_default}({stored_call_args});
            _attacking = false;
        }}
    }}

    fallback() external payable {{
        if (attackCount < 2 && !_attacking) {{
            attackCount++;
            _attacking = true;
            target.{fn_or_default}({stored_call_args});
            _attacking = false;
        }}
    }}
}}

/// @title Targeted reentrancy test for {finding.title}
/// @notice Auto-generated by contract-audit based on finding
contract Targeted_{contract_name}_{safe_fn}_Test is Test {{
    {contract_name} target;

    function setUp() public {{
        {setup_body}
    }}

    /// @notice Test reentrancy via ETH callback
    function test_reentrancy_{safe_fn}({param_decls}) public {{
        {contract_name}ReentrancyAttacker attacker = new {contract_name}ReentrancyAttacker(address(target));
        vm.deal(address(attacker), 100 ether);
        attacker.attack{{value: 1 ether}}({call_args});
        // A proper reentrancy guard prevents more than one entry
        assertLe(attacker.attackCount(), 1, "Reentrancy guard missing: function re-entered");
    }}
}}
"""


def _build_arithmetic_harness(
    contract_name: str,
    safe_fn: str,
    func_name: str,
    params: list[tuple[str, str]],
    param_decls: str,
    call_args: str,
    finding: Any,
    import_path: str,
    mock_code: str,
    setup_body: str,
) -> str:
    """Generate arithmetic boundary tests (0, 1, max) for the vulnerable function."""
    effective_params = params or [("uint256", "amount")]
    effective_decls = param_decls or "uint256 amount"
    effective_call = call_args or "amount"

    def _boundary_args(value: str) -> str:
        result = []
        replaced = False
        for t, n in effective_params:
            if not replaced and any(t.startswith(p) for p in ("uint", "int")):
                result.append(value)
                replaced = True
            else:
                result.append(n)
        if not replaced:
            result = [value] + [n for _, n in effective_params[1:]]
        return ", ".join(result)

    args_zero = _boundary_args("0")
    args_max = _boundary_args("type(uint256).max")
    args_one = _boundary_args("1")

    mock_section = f"\n{mock_code}\n" if mock_code else ""

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{import_path}";
{mock_section}
/// @title Targeted arithmetic test for {finding.title}
/// @notice Auto-generated by contract-audit based on finding
contract Targeted_{contract_name}_{safe_fn}_Test is Test {{
    {contract_name} target;

    function setUp() public {{
        {setup_body}
    }}

    /// @notice Fuzz test for {func_name or "target function"} with arbitrary inputs
    function testFuzz_{safe_fn}({effective_decls}) public {{
        target.{func_name}({effective_call});
    }}

    /// @notice Boundary: zero value should not cause unexpected behavior
    function test_{safe_fn}_zero() public {{
        target.{func_name}({args_zero});
    }}

    /// @notice Boundary: max uint256 should not overflow
    function test_{safe_fn}_max() public {{
        target.{func_name}({args_max});
    }}

    /// @notice Boundary: value of 1 (near-zero edge case)
    function test_{safe_fn}_one() public {{
        target.{func_name}({args_one});
    }}
}}
"""


def _build_access_control_harness(
    contract_name: str,
    safe_fn: str,
    func_name: str,
    params: list[tuple[str, str]],
    param_decls: str,
    call_args: str,
    finding: Any,
    import_path: str,
    mock_code: str,
    setup_body: str,
) -> str:
    """Generate access-control test that expects unauthorized callers to be rejected."""
    mock_section = f"\n{mock_code}\n" if mock_code else ""
    extra_params = (", " + param_decls) if param_decls else ""

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{import_path}";
{mock_section}
/// @title Targeted access-control test for {finding.title}
/// @notice Auto-generated by contract-audit based on finding
contract Targeted_{contract_name}_{safe_fn}_Test is Test {{
    {contract_name} target;

    function setUp() public {{
        {setup_body}
    }}

    /// @notice Unauthorized caller should be rejected
    function test_unauthorized_{safe_fn}({param_decls}) public {{
        address unauthorized = address(0xdead);
        vm.prank(unauthorized);
        vm.expectRevert();
        target.{func_name}({call_args});
    }}

    /// @notice Fuzz caller address — only owner/authorized should succeed
    function testFuzz_access_{safe_fn}(address caller{extra_params}) public {{
        vm.assume(caller != address(0));
        vm.prank(caller);
        try target.{func_name}({call_args}) {{
            // If this succeeds, verify caller was actually authorized
        }} catch {{
            // Expected for unauthorized callers
        }}
    }}
}}
"""
