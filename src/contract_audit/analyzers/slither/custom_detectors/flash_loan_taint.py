"""Custom Slither detector for flash loan taint analysis."""

from __future__ import annotations

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

    class FlashLoanTaintDetector(AbstractDetector):
        """Detects flash loan callback taint reaching sensitive sinks."""

        ARGUMENT = "flash-loan-taint"
        HELP = "Detects flash loan economic attack vectors"
        IMPACT = DetectorClassification.HIGH
        CONFIDENCE = DetectorClassification.MEDIUM

        WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation"
        WIKI_TITLE = "Flash Loan Taint"
        WIKI_DESCRIPTION = (
            "Flash loan callback functions can taint state without proper guards."
        )
        WIKI_EXPLOIT_SCENARIO = (
            "An attacker calls executeOperation() callback and manipulates "
            "state before repaying the flash loan."
        )
        WIKI_RECOMMENDATION = (
            "Verify flash loan source, use reentrancy guards, "
            "and validate state preconditions within callbacks."
        )

        FLASH_LOAN_CALLBACKS = {
            "executeOperation",
            "onFlashLoan",
            "uniswapV2Call",
            "pancakeCall",
            "balancerFlashLoan",
        }

        SENSITIVE_SINKS = {
            "transfer",
            "transferFrom",
            "safeTransfer",
            "safeTransferFrom",
            "_mint",
            "_burn",
        }

        def _detect(self) -> list:
            results = []
            for contract in self.slither.contracts:
                for func in contract.functions:
                    if func.name not in self.FLASH_LOAN_CALLBACKS:
                        continue

                    # Check if this callback reaches sensitive sinks
                    called_funcs: set[str] = set()
                    for node in func.nodes:
                        for ir in node.irs:
                            if hasattr(ir, "function_name"):
                                called_funcs.add(ir.function_name)

                    dangerous_sinks = called_funcs & self.SENSITIVE_SINKS
                    if dangerous_sinks:
                        info = [
                            "Flash loan callback ",
                            func,
                            f" reaches sensitive sink(s): {', '.join(dangerous_sinks)}\n",
                        ]
                        results.append(self.generate_result(info))
            return results

except ImportError:
    class FlashLoanTaintDetector:  # type: ignore[no-redef]
        ARGUMENT = "flash-loan-taint"
        HELP = "Slither not installed"
