"""Jinja2 template loader for LLM prompts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = Path(__file__).parent.parent.parent.parent / "config" / "llm_prompts"
_FALLBACK_DIR = Path(__file__).parent / "default_prompts"

# Fallback templates if file-based ones don't exist
FALLBACK_PROMPTS: dict[str, str] = {
    "explain.j2": """You are a smart contract security expert. Analyze this finding and provide a clear, detailed explanation.

Finding: {{ finding.title }}
Severity: {{ finding.severity.value }}
Category: {{ finding.category.value }}
Description: {{ finding.description }}

{% if source_snippet %}
Relevant code:
```solidity
{{ source_snippet }}
```
{% endif %}

Provide:
1. A clear explanation of why this is a vulnerability
2. The attack vector and potential impact
3. Any specific conditions required for exploitation
""",
    "remediate.j2": """You are a smart contract security expert. Provide a concrete remediation for this finding.

Finding: {{ finding.title }}
Severity: {{ finding.severity.value }}
Description: {{ finding.description }}

{% if source_snippet %}
Vulnerable code:
```solidity
{{ source_snippet }}
```
{% endif %}

Provide:
1. A specific code fix with before/after examples
2. Explanation of why the fix addresses the root cause
3. Any additional precautions to consider
""",
    "poc_generate.j2": """You are a smart contract security researcher. Generate a Foundry PoC test that demonstrates this vulnerability.

Finding: {{ finding.title }}
Severity: {{ finding.severity.value }}
Description: {{ finding.description }}
Locations: {{ finding.locations | map(attribute='file') | join(', ') }}

{% if source_snippet %}
Relevant code:
```solidity
{{ source_snippet }}
```
{% endif %}

Generate a complete Foundry test file (test/*.t.sol) that:
1. Deploys the vulnerable contract
2. Sets up the exploit conditions
3. Executes the attack
4. Verifies the vulnerability is triggered with assertions
""",
    "triage.j2": """You are a smart contract security expert performing false-positive triage.

Finding: {{ finding.title }}
Severity: {{ finding.severity.value }}
Detector: {{ finding.detector_name }}
Description: {{ finding.description }}

{% if source_snippet %}
Relevant code:
```solidity
{{ source_snippet }}
```
{% endif %}

Analyze whether this is a TRUE positive or FALSE positive.
Respond with JSON: {"is_false_positive": true/false, "reason": "brief explanation"}
""",
    "summarize.j2": """You are a smart contract security expert. Write an executive summary for this audit report.

Total findings: {{ findings | length }}
Critical: {{ findings | selectattr('severity.value', 'eq', 'Critical') | list | length }}
High: {{ findings | selectattr('severity.value', 'eq', 'High') | list | length }}
Medium: {{ findings | selectattr('severity.value', 'eq', 'Medium') | list | length }}

Key findings:
{% for f in findings[:5] %}
- [{{ f.severity.value }}] {{ f.title }}
{% endfor %}

Write a 2-3 paragraph executive summary covering:
1. Overall security posture
2. Most critical issues and their business impact
3. Recommended immediate actions
""",
}


def _get_env() -> Environment:
    """Get Jinja2 environment with template directories."""
    search_paths = []
    if _TEMPLATE_DIR.exists():
        search_paths.append(str(_TEMPLATE_DIR))

    if search_paths:
        return Environment(
            loader=FileSystemLoader(search_paths),
            autoescape=select_autoescape([]),
        )
    return Environment(autoescape=False)


def render_prompt(template_name: str, **kwargs: Any) -> str:
    """Render a prompt template with the given context variables."""
    env = _get_env()

    # Try to load from file first
    try:
        template = env.get_template(template_name)
        return template.render(**kwargs)
    except Exception:
        pass

    # Fall back to inline templates
    fallback = FALLBACK_PROMPTS.get(template_name, "")
    if fallback:
        template = env.from_string(fallback)
        return template.render(**kwargs)

    return f"Analyze this security finding: {kwargs.get('finding', {})}"
