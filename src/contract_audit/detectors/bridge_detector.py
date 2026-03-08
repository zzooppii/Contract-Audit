"""Cross-chain bridge vulnerability detector.

Detects missing chain ID validation, replay attacks, arbitrary delegatecall
in bridge contexts, and missing relayer validation.
"""

from __future__ import annotations

import logging
import re

from ..core.models import (
    AuditContext,
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)

logger = logging.getLogger(__name__)

# Patterns indicating bridge-related functionality
BRIDGE_INDICATORS = [
    r'\bbridge\b',
    r'\bBridge\b',
    r'\bcrossChain\b',
    r'\bCrossChain\b',
    r'\brelay\b',
    r'\bRelay\b',
    r'\bmessage\b.*\b(receive|send|verify)\b',
    r'\bchainId\b',
    r'\bsourceChain\b',
    r'\bdestChain\b',
    r'\block\w*\(',
    r'\bunlock\w*\(',
    r'\bmint\w*\(.*\b(to|recipient)\b',
]

# Access control patterns
ACCESS_CONTROL_PATTERNS = [
    r'\bonlyOwner\b',
    r'\bonlyAdmin\b',
    r'\bonlyRelayer\b',
    r'\bonlyBridge\b',
    r'\bonlyOperator\b',
    r'\bonlyRole\b',
    r'\bonlyAuthorized\b',
    r'require\s*\(\s*msg\.sender\s*==',
    r'require\s*\(\s*hasRole\s*\(',
    r'_checkRole\s*\(',
    r'if\s*\(\s*msg\.sender\s*!=',
]


def _strip_comments(source: str) -> str:
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    return source


def _strip_interfaces(source: str) -> str:
    result = []
    in_interface = False
    depth = 0
    for line in source.splitlines():
        if re.search(r'\binterface\s+\w+', line):
            in_interface = True
            depth = 0
        if in_interface:
            depth += line.count('{') - line.count('}')
            if depth <= 0 and '}' in line:
                in_interface = False
            continue
        result.append(line)
    return '\n'.join(result)


class BridgeDetector:
    """Detects cross-chain bridge vulnerabilities."""

    name = "bridge_detector"
    category = "bridge-vulnerability"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = _strip_comments(source)
            clean = _strip_interfaces(clean)

            # Only analyze contracts that look bridge-related
            bridge_score = sum(
                1 for pat in BRIDGE_INDICATORS if re.search(pat, clean, re.IGNORECASE)
            )
            if bridge_score < 2:
                continue

            lines = clean.splitlines()
            functions = self._extract_functions(lines)

            findings.extend(self._check_missing_chain_id(filename, clean, functions))
            findings.extend(self._check_replay_attack(filename, clean, functions))
            findings.extend(self._check_arbitrary_delegatecall(filename, functions))
            findings.extend(self._check_missing_relayer_validation(filename, functions))

        logger.info(f"Bridge detector found {len(findings)} findings")
        return findings

    def _check_missing_chain_id(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect message verification without chain ID binding."""
        findings: list[Finding] = []

        for func in functions:
            body = func['body']

            # Look for message hash/verification functions
            has_hash = bool(re.search(
                r'\b(keccak256|abi\.encode|abi\.encodePacked|ecrecover)\s*\(',
                body
            ))
            if not has_hash:
                continue

            # Check if function is related to message processing
            name_lower = func['name'].lower()
            is_message_func = any(kw in name_lower for kw in [
                'verify', 'process', 'receive', 'execute', 'relay', 'validate', 'hash',
            ])
            if not is_message_func:
                continue

            # Check for chain ID in the hash/encoding
            has_chain_id = bool(re.search(
                r'\bblock\.chainid\b|\bchainId\b|\bchain_id\b|\bsourceChainId\b|\bdestChainId\b',
                body
            ))

            if not has_chain_id:
                findings.append(
                    Finding(
                        title=f"Missing Chain ID in Message Verification: {func['name']}()",
                        description=(
                            f"`{func['name']}()` performs message hashing/verification "
                            "without including `block.chainid`. Messages signed for one "
                            "chain can be replayed on other chains (e.g., after a fork).\n\n"
                            "**Fix:** Include `block.chainid` in the message hash to "
                            "bind messages to a specific chain."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.BRIDGE_VULNERABILITY,
                        source=self.name,
                        detector_name="missing-chain-id",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings

    def _check_replay_attack(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect missing nonce/message ID tracking for replay prevention."""
        findings: list[Finding] = []

        # Look for message processing functions
        for func in functions:
            name_lower = func['name'].lower()
            is_process_func = any(kw in name_lower for kw in [
                'process', 'execute', 'receive', 'relay', 'claim', 'unlock', 'release',
            ])
            if not is_process_func:
                continue

            body = func['body']

            # Check for replay protection patterns
            has_replay_protection = bool(re.search(
                r'\bprocessed\b|\busedNonces\b|\bexecuted\b|\bclaimed\b|\b_used\b|'
                r'\bnonce\b.*\brequire\b|\brequire\b.*\bnonce\b|'
                r'require\s*\(\s*!\s*\w*(processed|executed|claimed|used)',
                body
            ))

            if not has_replay_protection:
                findings.append(
                    Finding(
                        title=f"Missing Replay Protection: {func['name']}()",
                        description=(
                            f"`{func['name']}()` processes cross-chain messages without "
                            "tracking processed message IDs/nonces. The same message "
                            "can be submitted multiple times to drain funds.\n\n"
                            "**Fix:** Track processed message hashes in a mapping and "
                            "reject duplicates: `require(!processed[msgHash]); processed[msgHash] = true;`"
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.BRIDGE_VULNERABILITY,
                        source=self.name,
                        detector_name="replay-attack",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings

    def _check_arbitrary_delegatecall(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect delegatecall to parameter-supplied addresses in bridge context."""
        findings: list[Finding] = []

        for func in functions:
            body = func['body']
            if not re.search(r'\.delegatecall\s*\(', body):
                continue

            # Check if target is a parameter
            params = re.findall(r'address\s+(\w+)', func['signature'])
            for param in params:
                if re.search(rf'{re.escape(param)}\s*\.\s*delegatecall', body):
                    findings.append(
                        Finding(
                            title=f"Arbitrary Delegatecall in Bridge: {func['name']}()",
                            description=(
                                f"`{func['name']}()` performs `delegatecall` to parameter `{param}`. "
                                "In a bridge context, this allows arbitrary code execution "
                                "in the contract's storage context, enabling theft of all "
                                "bridged assets.\n\n"
                                "**Fix:** Remove delegatecall or use a hardcoded trusted "
                                "implementation address."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=FindingCategory.BRIDGE_VULNERABILITY,
                            source=self.name,
                            detector_name="arbitrary-delegatecall",
                            locations=[
                                SourceLocation(
                                    file=filename,
                                    start_line=func['start'],
                                    end_line=func['start'],
                                    function=func['name'],
                                )
                            ],
                        )
                    )

        return findings

    def _check_missing_relayer_validation(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect token release/mint functions without access control."""
        findings: list[Finding] = []

        sensitive_patterns = [
            r'\b_mint\s*\(', r'\b_safeMint\s*\(',
            r'\.transfer\s*\(', r'\.safeTransfer\s*\(',
            r'\.call\s*\{?\s*value\s*:',
        ]

        for func in functions:
            if func['visibility'] not in ('external', 'public'):
                continue
            if func['is_view_pure']:
                continue

            name_lower = func['name'].lower()
            is_release_func = any(kw in name_lower for kw in [
                'release', 'unlock', 'mint', 'claim', 'withdraw', 'process',
            ])
            if not is_release_func:
                continue

            # Check for token transfers or mints in the body
            has_sensitive_op = any(
                re.search(pat, func['body']) for pat in sensitive_patterns
            )
            if not has_sensitive_op:
                continue

            # Check for access control
            full_text = func['signature'] + '\n' + func['body']
            has_access_control = any(
                re.search(pat, full_text) for pat in ACCESS_CONTROL_PATTERNS
            )

            if not has_access_control:
                findings.append(
                    Finding(
                        title=f"Missing Relayer Validation: {func['name']}()",
                        description=(
                            f"`{func['name']}()` releases tokens or mints assets "
                            "without checking that the caller is an authorized relayer. "
                            "Anyone can call this function to steal bridged assets.\n\n"
                            "**Fix:** Add `onlyRelayer` modifier or `require(msg.sender == relayer)` "
                            "check."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.BRIDGE_VULNERABILITY,
                        source=self.name,
                        detector_name="missing-relayer-validation",
                        locations=[
                            SourceLocation(
                                file=filename,
                                start_line=func['start'],
                                end_line=func['start'],
                                function=func['name'],
                            )
                        ],
                    )
                )

        return findings

    def _extract_functions(self, lines: list[str]) -> list[dict]:
        """Extract function declarations with their bodies."""
        functions = []
        i = 0
        while i < len(lines):
            func_match = re.search(r'\bfunction\s+(\w+)\s*\(', lines[i])
            if func_match:
                func_name = func_match.group(1)
                sig_lines = [lines[i]]
                j = i + 1
                brace_found = '{' in lines[i]
                while j < len(lines) and not brace_found:
                    sig_lines.append(lines[j])
                    if '{' in lines[j]:
                        brace_found = True
                    j += 1

                full_sig = ' '.join(sig_lines)

                visibility = 'internal'
                if 'external' in full_sig:
                    visibility = 'external'
                elif 'public' in full_sig:
                    visibility = 'public'

                is_view_pure = bool(re.search(r'\b(view|pure)\b', full_sig))

                depth = 0
                found_open = False
                body_lines = []
                for k in range(i, len(lines)):
                    body_lines.append(lines[k])
                    depth += lines[k].count('{') - lines[k].count('}')
                    if lines[k].count('{') > 0:
                        found_open = True
                    if found_open and depth <= 0:
                        break

                functions.append({
                    'name': func_name,
                    'start': i + 1,
                    'visibility': visibility,
                    'is_view_pure': is_view_pure,
                    'signature': full_sig,
                    'body': '\n'.join(body_lines),
                })

            i += 1

        return functions
