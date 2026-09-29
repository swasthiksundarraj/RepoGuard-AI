"""
Specification Conformance Checker
-----------------------------------
Implements the paper's "Specification Conformance Checker" (Section
III-B): validates findings and source files against project-specific
coding and naming conventions (default_spec.json), and marks each
finding produced by the other agents as spec_grounded when it is
consistent with -- and directly traceable to -- an explicit project
rule, versus a general best-practice heuristic.

This mirrors the paper's description of a validation stage that checks
generated findings against predefined specifications before the final
report is produced.
"""
from __future__ import annotations

import ast
import re
import uuid
from typing import List

from language_support import is_supported_source, language_for
from models import AgentName, Finding, Severity, SourceFile

# Rule IDs produced by other agents that correspond 1:1 to an explicit
# rule in the project specification, and are therefore "spec grounded".
SPEC_BACKED_RULES = {
    "SA-001": "max_function_lines",
    "SA-002": "max_function_args",
    "SA-003": "require_docstrings",
    "SA-005": "max_cyclomatic_complexity",
}


class SpecificationChecker:
    """Validates findings and source against explicit project rules."""

    name = "specification_checker"

    def __init__(self, spec: dict):
        self.spec = spec

    def ground(self, findings: List[Finding]) -> List[Finding]:
        """Mark which findings are directly traceable to an explicit rule."""
        for finding in findings:
            finding.spec_grounded = finding.rule_id in SPEC_BACKED_RULES
        return findings

    def _make(self, file, line, rule_id, title, desc, severity, confidence) -> Finding:
        return Finding(
            id=str(uuid.uuid4())[:8],
            agent=AgentName.SPEC,
            file=file,
            line=line,
            rule_id=rule_id,
            title=title,
            description=desc,
            severity=severity,
            confidence=confidence,
            spec_grounded=True,
        )

    def check_naming(self, files: List[SourceFile]) -> List[Finding]:
        """Independently check naming conventions and forbidden APIs."""
        findings: List[Finding] = []
        func_pattern = re.compile(self.spec.get("function_naming_pattern", ".*"))
        class_pattern = re.compile(self.spec.get("class_naming_pattern", ".*"))
        forbidden_functions = set(self.spec.get("forbidden_functions", []))
        forbidden_imports = set(self.spec.get("forbidden_imports", []))

        for source in files:
            if not is_supported_source(source.path):
                continue
            if language_for(source.path) != "python":
                continue
            try:
                tree = ast.parse(source.content, filename=source.path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not func_pattern.match(node.name) and not node.name.startswith("__"):
                        findings.append(self._make(
                            source.path, node.lineno, "SPEC-001",
                            "Function naming convention violation",
                            f"Function '{node.name}' does not match the "
                            f"required pattern '{self.spec.get('function_naming_pattern')}'.",
                            Severity.LOW, 0.9,
                        ))
                elif isinstance(node, ast.ClassDef):
                    if not class_pattern.match(node.name):
                        findings.append(self._make(
                            source.path, node.lineno, "SPEC-002",
                            "Class naming convention violation",
                            f"Class '{node.name}' does not match the "
                            f"required pattern '{self.spec.get('class_naming_pattern')}'.",
                            Severity.LOW, 0.9,
                        ))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in forbidden_imports:
                            findings.append(self._make(
                                source.path, node.lineno, "SPEC-003",
                                "Forbidden import",
                                f"Importing '{alias.name}' is disallowed by "
                                "project policy.",
                                Severity.MEDIUM, 0.9,
                            ))
                elif isinstance(node, ast.Call):
                    fname = self._call_name(node)
                    if fname in forbidden_functions:
                        findings.append(self._make(
                            source.path, node.lineno, "SPEC-004",
                            "Forbidden function call",
                            f"Calling '{fname}' is disallowed by project policy.",
                            Severity.MEDIUM, 0.9,
                        ))
        return findings

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Attribute):
            base = func.value
            base_name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
            return f"{base_name}.{func.attr}"
        if isinstance(func, ast.Name):
            return func.id
        return ""
