"""HTML audit report generator using Jinja2 templates."""

from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment

from ...core.models import AuditResult

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Smart Contract Audit Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
    sans-serif; max-width: 1200px; margin: 0 auto;
    padding: 2rem; color: #333; }
  h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 0.5rem; }
  h2 { color: #16213e; margin-top: 2rem; }
  h3 { color: #0f3460; }
  .summary-grid { display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 1rem; margin: 1rem 0; }
  .summary-card { padding: 1rem; border-radius: 8px; text-align: center; }
  .critical { background: #ff000020; border: 2px solid #ff0000; }
  .high { background: #ff660020; border: 2px solid #ff6600; }
  .medium { background: #ffaa0020; border: 2px solid #ffaa00; }
  .low { background: #00aaff20; border: 2px solid #00aaff; }
  .info { background: #f0f0f0; border: 2px solid #999; }
  .count { font-size: 2rem; font-weight: bold; }
  .finding { border: 1px solid #ddd; border-radius: 8px; margin: 1rem 0; padding: 1.5rem; }
  .finding-header { display: flex; justify-content: space-between; align-items: center; }
  .badge { padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: bold; font-size: 0.85rem; }
  .badge-critical { background: #ff0000; color: white; }
  .badge-high { background: #ff6600; color: white; }
  .badge-medium { background: #ffaa00; color: #333; }
  .badge-low { background: #00aaff; color: white; }
  .badge-info { background: #999; color: white; }
  .location { font-family: monospace; background: #f5f5f5;
    padding: 0.25rem 0.5rem; border-radius: 4px;
    font-size: 0.9rem; }
  pre { background: #1a1a2e; color: #e0e0e0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
  code { font-family: 'Courier New', monospace; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.75rem; border: 1px solid #ddd; text-align: left; }
  th { background: #16213e; color: white; }
  tr:nth-child(even) { background: #f9f9f9; }
  .risk-score { font-size: 2rem; font-weight: bold;
    color: {% if result.summary.overall_risk_score >= 7 %}#ff0000
    {%- elif result.summary.overall_risk_score >= 4 %}#ff6600
    {%- else %}#00aa00{% endif %}; }
  .suppressed { opacity: 0.5; text-decoration: line-through; }
</style>
</head>
<body>
<h1>🔍 Smart Contract Security Audit Report</h1>

<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Engine</td><td>contract-audit v{{ result.metadata.engine_version }}</td></tr>
  <tr><td>Contracts Analyzed</td><td>{{ result.metadata.contract_count }}</td></tr>
  <tr><td>Risk Score</td><td class="risk-score">{{ result.summary.overall_risk_score }}/10</td></tr>
</table>

<h2>Summary</h2>
<div class="summary-grid">
  {% if result.summary.critical_count > 0 %}
  <div class="summary-card critical">
    <div class="count">{{ result.summary.critical_count }}</div>
    <div>Critical</div>
  </div>
  {% endif %}
  {% if result.summary.high_count > 0 %}
  <div class="summary-card high">
    <div class="count">{{ result.summary.high_count }}</div>
    <div>High</div>
  </div>
  {% endif %}
  {% if result.summary.medium_count > 0 %}
  <div class="summary-card medium">
    <div class="count">{{ result.summary.medium_count }}</div>
    <div>Medium</div>
  </div>
  {% endif %}
  {% if result.summary.low_count > 0 %}
  <div class="summary-card low">
    <div class="count">{{ result.summary.low_count }}</div>
    <div>Low</div>
  </div>
  {% endif %}
</div>

<h2>Findings</h2>
{% for finding in result.active_findings %}
<div class="finding">
  <div class="finding-header">
    <h3>{{ finding.title }}</h3>
    <span class="badge badge-{{ finding.severity.value | lower }}">
      {{- finding.severity.value }}</span>
  </div>
  <table>
    <tr><th>Risk Score</th><td>{{ finding.risk_score }}</td>
        <th>Confidence</th><td>{{ finding.confidence.value }}</td></tr>
    <tr><th>Category</th><td>{{ finding.category.value }}</td>
        <th>Source</th><td>{{ finding.source }}</td></tr>
  </table>
  {% if finding.locations %}
  <p><strong>Location:</strong>
    {% for loc in finding.locations[:3] %}
    <span class="location">{{ loc.file }}:{{ loc.start_line }}</span>
    {% endfor %}
  </p>
  {% endif %}
  <p>{{ finding.description }}</p>
  {% if finding.llm_explanation %}
  <details>
    <summary><strong>AI Analysis</strong></summary>
    <p>{{ finding.llm_explanation }}</p>
  </details>
  {% endif %}
  {% if finding.llm_remediation %}
  <details>
    <summary><strong>Remediation</strong></summary>
    <p>{{ finding.llm_remediation }}</p>
  </details>
  {% endif %}
  {% if finding.llm_poc %}
  <details>
    <summary><strong>Proof of Concept</strong></summary>
    <pre><code>{{ finding.llm_poc }}</code></pre>
  </details>
  {% endif %}
</div>
{% endfor %}

<hr>
<p><em>Generated by contract-audit v{{ result.metadata.engine_version }}</em></p>
</body>
</html>
"""


def generate_html(result: AuditResult) -> str:
    """Generate HTML audit report."""
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    return template.render(result=result)


def write_html(result: AuditResult, output_path: Path) -> None:
    """Write HTML report to file."""
    content = generate_html(result)
    output_path.write_text(content)
