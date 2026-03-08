"""NFT vulnerability detector.

Detects unsafe mint, reentrancy via ERC721 callbacks, missing exists checks,
and unlimited approval issues.
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


def _strip_comments(source: str) -> str:
    """Remove single-line and multi-line comments."""
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    return source


def _strip_interfaces(source: str) -> str:
    """Remove interface declarations."""
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


class NFTDetector:
    """Detects NFT-specific vulnerabilities."""

    name = "nft_detector"
    category = "nft-vulnerability"
    required_context = ["contract_sources"]

    async def detect(self, context: AuditContext) -> list[Finding]:
        findings: list[Finding] = []

        for filename, source in context.contract_sources.items():
            clean = _strip_comments(source)
            clean = _strip_interfaces(clean)

            # Only run on contracts that look NFT-related
            # Require at least one NFT-specific keyword (not just _mint which ERC20 also uses)
            if not re.search(r'\b(ERC721|ERC1155|tokenURI|ownerOf|_safeMint|onERC721Received|safeTransferFrom)\b', clean):
                continue

            lines = clean.splitlines()
            functions = self._extract_functions(lines)

            findings.extend(self._check_unsafe_mint(filename, clean, functions))
            findings.extend(self._check_reentrancy_via_callback(filename, functions))
            findings.extend(self._check_missing_exists_check(filename, functions))
            findings.extend(self._check_unlimited_approval(filename, clean, functions))

        logger.info(f"NFT detector found {len(findings)} findings")
        return findings

    def _check_unsafe_mint(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect use of _mint() instead of _safeMint().

        _mint() doesn't check if the recipient can handle ERC721 tokens,
        which can lead to tokens being permanently locked.
        """
        findings: list[Finding] = []

        for func in functions:
            body = func['body']

            # Look for _mint() usage
            if not re.search(r'\b_mint\s*\(', body):
                continue

            # Skip if _safeMint is also used (they might have both for different reasons)
            if re.search(r'\b_safeMint\s*\(', body):
                continue

            # Skip if there's an onERC721Received check
            if re.search(r'\bonERC721Received\b', body):
                continue

            findings.append(
                Finding(
                    title=f"Unsafe Mint in {func['name']}()",
                    description=(
                        f"`{func['name']}()` uses `_mint()` instead of `_safeMint()`. "
                        "If the recipient is a contract that doesn't implement "
                        "`onERC721Received`, the token will be permanently locked.\n\n"
                        "**Fix:** Replace `_mint()` with `_safeMint()` to ensure "
                        "the recipient can handle ERC721 tokens."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=FindingCategory.NFT_VULNERABILITY,
                    source=self.name,
                    detector_name="unsafe-mint",
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

    def _check_reentrancy_via_callback(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect state changes after safeTransferFrom/_safeMint.

        These functions invoke onERC721Received/onERC1155Received callbacks
        which can be used for reentrancy.
        """
        findings: list[Finding] = []

        callback_patterns = [
            r'\bsafeTransferFrom\s*\(',
            r'\b_safeMint\s*\(',
            r'\bsafeTransfer\s*\(',
            r'\b_safeTransfer\s*\(',
        ]

        state_update = re.compile(
            r'\b(\w+)\s*(?:\[.*?\])?\s*(?:=|\+=|-=)\s*'
        )

        for func in functions:
            if func['is_view_pure']:
                continue

            body_lines = func['body'].splitlines()
            callback_line = -1

            for idx, line in enumerate(body_lines):
                if any(re.search(pat, line) for pat in callback_patterns):
                    callback_line = idx

                if callback_line >= 0 and idx > callback_line:
                    match = state_update.search(line)
                    if match:
                        var_name = match.group(1)
                        # Skip local variable declarations
                        if re.search(rf'\b(uint|int|bool|address|bytes|string)\b.*\b{re.escape(var_name)}\b', line):
                            continue

                        findings.append(
                            Finding(
                                title=f"Reentrancy via NFT Callback in {func['name']}()",
                                description=(
                                    f"`{func['name']}()` modifies state variable `{var_name}` "
                                    "after a safe transfer/mint call. The `onERC721Received` "
                                    "callback can be used to re-enter the contract before "
                                    "state is updated.\n\n"
                                    "**Fix:** Move state updates before `safeTransferFrom`/"
                                    "`_safeMint` calls, or add a `nonReentrant` modifier."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                category=FindingCategory.NFT_VULNERABILITY,
                                source=self.name,
                                detector_name="nft-callback-reentrancy",
                                locations=[
                                    SourceLocation(
                                        file=filename,
                                        start_line=func['start'] + idx,
                                        end_line=func['start'] + idx,
                                        function=func['name'],
                                    )
                                ],
                                metadata={"variable": var_name},
                            )
                        )
                        break

        return findings

    def _check_missing_exists_check(
        self, filename: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect tokenURI and similar functions missing _exists() check."""
        findings: list[Finding] = []

        target_functions = {'tokenURI', 'getApproved', 'tokenMetadata'}

        for func in functions:
            if func['name'] not in target_functions:
                continue

            body = func['body']

            # Check for _exists() or _requireOwned or ownerOf or _ownerOf
            has_exists = bool(re.search(
                r'\b(_exists|_requireOwned|_requireMinted|ownerOf|_ownerOf)\s*\(',
                body
            ))
            has_require = bool(re.search(r'require\s*\(', body))

            if not has_exists and not has_require:
                findings.append(
                    Finding(
                        title=f"Missing Token Existence Check in {func['name']}()",
                        description=(
                            f"`{func['name']}()` does not check if the token exists before "
                            "operating on it. Querying a non-existent token should revert "
                            "per the ERC-721 spec.\n\n"
                            "**Fix:** Add `require(_exists(tokenId))` or use `_requireOwned(tokenId)` "
                            "at the start of the function."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=FindingCategory.NFT_VULNERABILITY,
                        source=self.name,
                        detector_name="missing-exists-check",
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

    def _check_unlimited_approval(
        self, filename: str, source: str, functions: list[dict]
    ) -> list[Finding]:
        """Detect setApprovalForAll overrides without additional validation."""
        findings: list[Finding] = []

        for func in functions:
            if func['name'] != 'setApprovalForAll':
                continue

            body = func['body']

            # Check if there's any custom validation beyond the parent call
            has_validation = bool(re.search(
                r'require\s*\(|revert\s|if\s*\(.*(?:!=|==|>|<)',
                body
            ))

            # Check if it's just calling super
            is_just_super = bool(re.search(r'super\.setApprovalForAll', body)) and not has_validation

            if is_just_super or not has_validation:
                findings.append(
                    Finding(
                        title="Unrestricted setApprovalForAll Override",
                        description=(
                            "`setApprovalForAll()` is overridden but lacks additional "
                            "validation. Consider adding restrictions like preventing "
                            "approval of known malicious operators or adding a timelock.\n\n"
                            "**Fix:** Add validation such as operator whitelist check "
                            "or emit a warning event for monitoring."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category=FindingCategory.NFT_VULNERABILITY,
                        source=self.name,
                        detector_name="unlimited-approval",
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
