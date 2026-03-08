"""Shared utility functions for Solidity source code processing.

Used by multiple detectors to strip comments, interfaces, and extract functions.
"""

from __future__ import annotations

import re


def strip_comments(source: str) -> str:
    """Remove single-line (//) and multi-line (/* */) comments."""
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    return source


def strip_interfaces(source: str) -> str:
    """Remove interface declarations (interface Foo { ... })."""
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


def extract_functions(source: str) -> list[dict]:
    """Extract function declarations with bodies from Solidity source.

    Returns list of dicts with keys:
        name, start, visibility, is_view_pure, signature, body
    """
    functions = []
    lines = source.splitlines()
    in_interface = False
    interface_depth = 0

    i = 0
    while i < len(lines):
        line = lines[i]

        if re.search(r'\binterface\s+\w+', line):
            in_interface = True
            interface_depth = 0

        if in_interface:
            interface_depth += line.count('{') - line.count('}')
            if interface_depth <= 0 and '}' in line:
                in_interface = False
            i += 1
            continue

        func_match = re.search(r'\bfunction\s+(\w+)\s*\(', line)
        if func_match:
            func_name = func_match.group(1)

            # Collect full signature (may span multiple lines)
            sig_lines = [line]
            j = i + 1
            brace_found = '{' in line
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
            elif 'private' in full_sig:
                visibility = 'private'

            is_view_pure = bool(re.search(r'\b(view|pure)\b', full_sig))

            # Extract body
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

            body = '\n'.join(body_lines)

            functions.append({
                'name': func_name,
                'start': i + 1,
                'visibility': visibility,
                'is_view_pure': is_view_pure,
                'signature': full_sig,
                'body': body,
            })

        i += 1

    return functions
