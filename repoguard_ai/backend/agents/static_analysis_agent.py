"""
Static Analysis Agent
-----------------------
Implements the paper's "Static Analysis Agent" (Section III-B):
deterministic, rule-based analysis using Abstract Syntax Tree (AST)
parsing, without executing the target program. Detects structural and
coding-standard issues such as missing docstrings, overly long
functions, too many parameters, bare excepts, mutable default
arguments, wildcard imports, and cyclomatic complexity.
"""
from __future__ import annotations

import ast
import re
import uuid
from typing import List

from language_support import is_supported_source, language_for
from models import AgentName, Finding, Severity, SourceFile

BRANCH_NODES = (
    ast.If, ast.For, ast.While, ast.Try, ast.With,
    ast.BoolOp, ast.ExceptHandler,
)


def _cyclomatic_complexity(node: ast.AST) -> int:
    complexity = 1
    for child in ast.walk(node):
        if isinstance(child, BRANCH_NODES):
            complexity += 1
    return complexity


class StaticAnalysisAgent:
    """Deterministic AST + rule based static analysis for Python files."""

    name = "static_analysis"

    def __init__(self, spec: dict):
        self.spec = spec

    def _make(self, file, line, rule_id, title, desc, severity, confidence, suggestion=None) -> Finding:
        return Finding(
            id=str(uuid.uuid4())[:8],
            agent=AgentName.STATIC,
            file=file,
            line=line,
            rule_id=rule_id,
            title=title,
            description=desc,
            severity=severity,
            confidence=confidence,
            suggestion=suggestion,
        )

    def analyze_file(self, source: SourceFile) -> List[Finding]:
        findings: List[Finding] = []
        if not is_supported_source(source.path):
            return findings

        if language_for(source.path) == "python":
            try:
                tree = ast.parse(source.content, filename=source.path)
            except SyntaxError as exc:
                return [self._make(
                    source.path, exc.lineno or 0, "SA-000", "Syntax error",
                    f"The file could not be parsed: {exc.msg}",
                    Severity.CRITICAL, 0.99,
                    "Fix the reported syntax error before further analysis is possible.",
                )]

            max_lines = self.spec.get("max_function_lines", 50)
            max_args = self.spec.get("max_function_args", 5)
            max_cc = self.spec.get("max_cyclomatic_complexity", 10)

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    findings.extend(self._check_function(source.path, node, max_lines, max_args, max_cc))
                elif isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        findings.append(self._make(
                            source.path, node.lineno, "SA-010", "Bare except clause",
                            "A bare 'except:' catches every exception, including "
                            "KeyboardInterrupt and SystemExit, hiding real errors.",
                            Severity.MEDIUM, 0.85,
                            "Catch a specific exception type instead of a bare except.",
                        ))
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name == "*":
                            findings.append(self._make(
                                source.path, node.lineno, "SA-020", "Wildcard import",
                                f"'from {node.module} import *' pollutes the namespace "
                                "and makes it unclear where names originate.",
                                Severity.LOW, 0.8,
                                "Import only the specific names that are needed.",
                            ))
            return findings

        for idx, line in enumerate(source.content.splitlines(), start=1):
            if len(line) > 120:
                findings.append(self._make(
                    source.path, idx, "SA-101", "Long line",
                    f"Line exceeds the recommended width for {language_for(source.path)} source ({len(line)} chars).",
                    Severity.INFO, 0.6,
                    "Wrap or refactor long statements for readability and maintainability.",
                ))
            if re.search(r"\b(TODO|FIXME|HACK)\b", line, re.IGNORECASE):
                findings.append(self._make(
                    source.path, idx, "SA-102", "Unresolved task marker",
                    "A TODO/FIXME marker indicates incomplete or provisional logic.",
                    Severity.LOW, 0.65,
                    "Resolve or track the outstanding task before shipping.",
                ))
            if re.search(r"\b(gets|strcpy|sprintf|scanf)\s*\(", line):
                findings.append(self._make(
                    source.path, idx, "SA-103", "Unsafe legacy buffer API",
                    f"Unsafe '{line.strip()}' usage can lead to buffer overflows or code execution issues.",
                    Severity.HIGH, 0.8,
                    "Use safer bounded APIs or validated input handling instead.",
                ))
            if re.search(r"(?<![A-Za-z0-9_])(\d{2,})(?![A-Za-z0-9_])", line):
                if not re.search(r"(main\s*\(|#define|const\s+\w+\s*=|static\s+.*=|final\s+.*=)", line):
                    findings.append(self._make(
                        source.path, idx, "SA-104", "Magic number literal",
                        "A literal constant appears inline without an explanatory named constant.",
                        Severity.INFO, 0.5,
                        "Extract the value into a named constant to clarify intent.",
                    ))
        return findings

    def _check_function(self, path, node, max_lines, max_args, max_cc) -> List[Finding]:
        findings: List[Finding] = []
        func_lines = (node.end_lineno or node.lineno) - node.lineno + 1
        n_args = len(node.args.args)
        has_docstring = ast.get_docstring(node) is not None

        if func_lines > max_lines:
            findings.append(self._make(
                path, node.lineno, "SA-001", "Function too long",
                f"'{node.name}' spans {func_lines} lines, exceeding the "
                f"project limit of {max_lines}. Long functions are harder "
                "to test and reason about.",
                Severity.MEDIUM, 0.75,
                "Split this function into smaller, single-purpose functions.",
            ))

        if n_args > max_args:
            findings.append(self._make(
                path, node.lineno, "SA-002", "Too many parameters",
                f"'{node.name}' has {n_args} parameters, exceeding the "
                f"project limit of {max_args}.",
                Severity.LOW, 0.7,
                "Group related parameters into a dataclass or config object.",
            ))

        if self.spec.get("require_docstrings", True) and not has_docstring and not node.name.startswith("_"):
            findings.append(self._make(
                path, node.lineno, "SA-003", "Missing docstring",
                f"Public function '{node.name}' has no docstring.",
                Severity.INFO, 0.6,
                "Add a docstring describing purpose, arguments, and return value.",
            ))

        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                findings.append(self._make(
                    path, node.lineno, "SA-004", "Mutable default argument",
                    f"'{node.name}' uses a mutable default argument, which is "
                    "shared across calls and can cause subtle bugs.",
                    Severity.MEDIUM, 0.8,
                    "Use None as the default and initialize the mutable value inside the function.",
                ))

        cc = _cyclomatic_complexity(node)
        if cc > max_cc:
            findings.append(self._make(
                path, node.lineno, "SA-005", "High cyclomatic complexity",
                f"'{node.name}' has an estimated cyclomatic complexity of {cc}, "
                f"exceeding the project limit of {max_cc}.",
                Severity.MEDIUM, 0.65,
                "Reduce branching by extracting helper functions or simplifying logic.",
            ))

        return findings

    def analyze(self, files: List[SourceFile]) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            findings.extend(self.analyze_file(f))
        return findings
