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


def _get_default_value_for_abi_type(
    inp: dict[str, Any],
    contract_name: str,
    mock_counter_ref: list[int],
    mocks_needed: set[str],
    setup_lines: list[str],
) -> str:
    """Solidity ABI 타입에 대한 문법 정합적 디폴트/모킹 리터럴 값을 반환하는 재귀 헬퍼 함수."""
    type_ = inp.get("type", "")
    raw_name = inp.get("name", "")
    name_lower = raw_name.lower().lstrip("_")

    if type_ == "address":
        mc = mock_counter_ref[0]
        mock_counter_ref[0] += 1
        if any(h in name_lower for h in _TOKEN_HINTS):
            mocks_needed.add("erc20")
            var = f"mockToken{mc}"
            setup_lines.append(f"MockERC20 {var} = new MockERC20();")
            setup_lines.append(f"{var}.mint(address(this), 1_000_000e18);")
            return f"address({var})"
        elif any(h in name_lower for h in _ORACLE_HINTS):
            mocks_needed.add("oracle")
            var = f"mockOracle{mc}"
            setup_lines.append(f"MockOracle {var} = new MockOracle();")
            return f"address({var})"
        else:
            return f"address({mc + 1})"

    elif type_.startswith("uint") or type_.startswith("int"):
        if any(h in name_lower for h in _TIME_HINTS):
            return "3600"
        elif any(h in name_lower for h in _AMOUNT_HINTS):
            return "1_000_000e18"
        else:
            return "100"

    elif type_ == "bool":
        return "true"
    elif type_ == "bytes32":
        return "bytes32(0)"
    elif type_ in ("string",):
        return '""'
    elif type_ in ("bytes",):
        return '""'
    elif type_.endswith("[]"):
        # 동적 배열
        base_type = type_[:-2]
        internal_type = inp.get("internalType", "")
        if internal_type.startswith("struct ") and internal_type.endswith("[]"):
            struct_type = internal_type[7:-2]
            if "." not in struct_type:
                struct_type = f"{contract_name}.{struct_type}"
            return f"new {struct_type}[](0)"
        return f"new {base_type}[](0)"
    elif re.match(r'.+\[\d+\]$', type_):
        # 고정 크기 배열
        match = re.match(r'(.+)\[(\d+)\]$', type_)
        if match:
            base_type = match.group(1)
            size = int(match.group(2))

            # 배열 요소에 대해서는 모킹 주소를 매핑하지 않고 일반 디폴트 값으로 지정
            if base_type == "address":
                default_val = "address(0)"
            elif base_type.startswith("uint") or base_type.startswith("int"):
                default_val = "0"
            elif base_type == "bool":
                default_val = "false"
            elif base_type == "bytes32":
                default_val = "bytes32(0)"
            else:
                dummy_inp = {"type": base_type, "name": raw_name}
                default_val = _get_default_value_for_abi_type(dummy_inp, contract_name, mock_counter_ref, mocks_needed, setup_lines)
            return f"[{', '.join(default_val for _ in range(size))}]"
        return "new uint256[](0)" # 예외 방어
    elif type_.startswith("(") and type_.endswith(")"):
        # 괄호 제거 후 콤마 분리 (익명 튜플 문자열 파싱)
        inner = type_[1:-1]
        parts = []
        depth = 0
        current: list[str] = []
        for char in inner:
            if char == "," and depth == 0:
                parts.append("".join(current).strip())
                current = []
            else:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                current.append(char)
        if current:
            parts.append("".join(current).strip())

        component_vals = []
        for part in parts:
            dummy_inp = {"type": part, "name": raw_name}
            val = _get_default_value_for_abi_type(dummy_inp, contract_name, mock_counter_ref, mocks_needed, setup_lines)
            component_vals.append(val)
        return f"({', '.join(component_vals)})"
    elif type_ == "tuple" or "tuple" in type_:
        # 구조체 / 튜플
        components = inp.get("components", [])
        component_vals = []
        for comp in components:
            val = _get_default_value_for_abi_type(comp, contract_name, mock_counter_ref, mocks_needed, setup_lines)
            component_vals.append(val)

        internal_type = inp.get("internalType", "")
        if internal_type.startswith("struct "):
            struct_type = internal_type[7:]
            # struct 이름에 소속 계약(Contract)명이 명시되어 있지 않은 경우, 타겟 계약 이름을 붙여줌
            if "." not in struct_type:
                struct_type = f"{contract_name}.{struct_type}"
            return f"{struct_type}({', '.join(component_vals)})"

        # 이름 없는 튜플인 경우, 튜플 리터럴 리턴
        return f"({', '.join(component_vals)})"
    else:
        # 알 수 없는 스칼라 타입 캐스팅 처리
        return f"{type_}(0)"


def _build_constructor_setup(
    contract_name: str,
    constructor_inputs: list[dict[str, Any]] | None,
) -> tuple[str, str]:
    """Foundry setUp() 함수 내부 바디 코드 및 필요 모의 계약 코드를 생성합니다."""
    if not constructor_inputs:
        return "", f"target = new {contract_name}();"

    mocks_needed: set[str] = set()
    setup_lines: list[str] = []
    ctor_args: list[str] = []
    mock_counter = [0] # 재귀 전달용 레퍼런스 공유 리스트

    for inp in constructor_inputs:
        val = _get_default_value_for_abi_type(inp, contract_name, mock_counter, mocks_needed, setup_lines)
        ctor_args.append(val)

    # 모킹에 사용된 코드 블록 결합
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
    try:
        mock_code, setup_body = _build_constructor_setup(contract_name, constructor_abi)
    except ValueError as e:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            f"Skipping fuzz harness generation for {contract_name}: {e}"
        )
        return Path("")

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

    try:
        mock_code, setup_body = _build_constructor_setup(contract_name, constructor_abi)
    except ValueError as e:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            f"Skipping targeted harness generation for {contract_name}: {e}"
        )
        return Path("")

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
