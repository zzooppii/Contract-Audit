"""Custom Slither detector for oracle price manipulation vulnerabilities."""

from __future__ import annotations

from typing import Any

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class OracleManipulationDetector(AbstractDetector):  # type: ignore[misc]
        """Detects oracle price reads without staleness checks."""

        ARGUMENT = "oracle-manipulation"
        HELP = "Detects oracle price manipulation vulnerabilities"
        IMPACT = DetectorClassification.HIGH
        CONFIDENCE = DetectorClassification.MEDIUM

        WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation"
        WIKI_TITLE = "Oracle Manipulation"
        WIKI_DESCRIPTION = (
            "Oracle reads without staleness checks can be manipulated "
            "via flash loans or stale data."
        )
        WIKI_EXPLOIT_SCENARIO = (
            "An attacker uses a flash loan to manipulate the spot price "
            "of a Uniswap pool and calls borrow() before the block ends."
        )
        WIKI_RECOMMENDATION = (
            "Use TWAP oracles with adequate periods (30 minutes minimum). "
            "Check updatedAt from Chainlink and revert if stale."
        )

        ORACLE_FUNCTIONS = {
            "latestRoundData",
            "latestAnswer",
            "getReserves",
            "slot0",
            "observe",
            "consult",
        }

        STALENESS_CHECKS = {
            "updatedAt",
            "answeredInRound",
            "timestamp",
        }

        def _detect(self) -> list[Any]:
            results = []
            for contract in self.slither.contracts:
                for func in contract.functions:
                    oracle_reads = []
                    has_staleness_check = False

                    for node in func.nodes:
                        for ir in node.irs:
                            if hasattr(ir, "function_name"):
                                if ir.function_name in self.ORACLE_FUNCTIONS:
                                    oracle_reads.append((node, ir))
                                if ir.function_name in self.STALENESS_CHECKS:
                                    has_staleness_check = True

                    if oracle_reads and not has_staleness_check:
                        info = [
                            "Oracle read without staleness check in ",
                            func,
                            "\n",
                        ]
                        results.append(self.generate_result(info))
            return results

except ImportError:
    # Slither not installed; provide a stub
    class OracleManipulationDetector:  # type: ignore[no-redef]
        ARGUMENT = "oracle-manipulation"
        HELP = "Slither not installed"
