"""
Taint & Data-Flow Analysis Agent
---------------------------------
Performs static data-flow and taint analysis by tracing untrusted inputs
(Sources) through variable assignments and transformations to security-sensitive
operations (Sinks).

Identifies:
- Command Injection (CWE-78): Tainted data flowing into os.system, subprocess with shell=True
- SQL Injection (CWE-89): Tainted data flowing into database cursor.execute()
- Remote Code Execution (CWE-95): Tainted data flowing into eval() or exec()
- Insecure Deserialization (CWE-502): Tainted data flowing into pickle.loads()
"""
from __future__ import annotations

import ast
import re
import uuid
from typing import Dict, List, Set

from language_support import is_supported_source, language_for
from models import AgentName, Finding, Severity, SourceFile

TAINT_SOURCES = {"input", "sys.argv", "os.environ.get", "request.args.get", "request.form.get"}

DANGEROUS_SINKS = {
    "os.system": ("TAINT-001", "CWE-78", "Command Injection via Tainted Data Flow",
                  Severity.CRITICAL, "Pass arguments as a validated list with shell=False."),
    "subprocess.call": ("TAINT-002", "CWE-78", "Shell Injection via Tainted Argument",
                        Severity.HIGH, "Use subprocess.run([cmd, arg], shell=False)."),
    "cursor.execute": ("TAINT-003", "CWE-89", "SQL Injection via Tainted Query Construction",
                       Severity.CRITICAL, "Use parameterized placeholders (e.g. %s or ?) rather than string concatenation."),
    "eval": ("TAINT-004", "CWE-95", "Arbitrary Code Execution via Tainted Input to eval()",
             Severity.CRITICAL, "Avoid eval(); parse input using ast.literal_eval() or structured schemas."),
    "exec": ("TAINT-005", "CWE-95", "Arbitrary Code Execution via Tainted Input to exec()",
             Severity.CRITICAL, "Avoid exec(); dynamically evaluate data, not executable code."),
    "pickle.loads": ("TAINT-006", "CWE-502", "Insecure Deserialization of Tainted Object",
                     Severity.HIGH, "Deserialize using safe formats like JSON or Protocol Buffers."),
}


class TaintVisitor(ast.NodeVisitor):
    """Tracks intra-procedural taint flow from parameters/inputs to dangerous sinks."""

    def __init__(self, filename: str):
        self.filename = filename
        self.tainted_vars: Set[str] = set()
        self.taint_sources_map: Dict[str, str] = {}  # var -> source description
        self.findings: List[Finding] = []

    def _call_repr(self, node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            val = func.value
            val_id = val.id if isinstance(val, ast.Name) else getattr(val, "attr", "")
            return f"{val_id}.{func.attr}"
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Function parameters are considered external entrypoints (taint sources)
        local_visitor = TaintVisitor(self.filename)
        for arg in node.args.args:
            arg_name = arg.arg
            if arg_name not in ("self", "cls"):
                local_visitor.tainted_vars.add(arg_name)
                local_visitor.taint_sources_map[arg_name] = f"parameter '{arg_name}' of '{node.name}()' at L{node.lineno}"

        # Visit function body with localized taint tracking
        for stmt in node.body:
            local_visitor.visit(stmt)

        self.findings.extend(local_visitor.findings)

    def visit_Assign(self, node: ast.Assign):
        # Track taint propagation across assignments: y = x + 1
        is_source = False
        source_desc = ""

        # Check if right-hand side is a known source call
        if isinstance(node.value, ast.Call):
            call_name = self._call_repr(node.value)
            if any(src in call_name for src in TAINT_SOURCES):
                is_source = True
                source_desc = f"call to '{call_name}' at L{node.lineno}"

        # Check if right-hand side uses existing tainted variables
        used_tainted = []
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                used_tainted.append(child.id)

        if used_tainted:
            is_source = True
            first_tainted = used_tainted[0]
            source_desc = f"{self.taint_sources_map.get(first_tainted, first_tainted)} (propagated via L{node.lineno})"

        if is_source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    self.taint_sources_map[target.id] = source_desc

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._call_repr(node)
        
        # Check if dangerous sink
        if call_name in DANGEROUS_SINKS:
            rule_id, cwe, title, severity, suggestion = DANGEROUS_SINKS[call_name]
            
            # Check if any argument is tainted or involves tainted variables
            taint_hit = None
            for arg in node.args:
                for child in ast.walk(arg):
                    if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                        taint_hit = child.id
                        break
                if taint_hit:
                    break

            if taint_hit:
                origin = self.taint_sources_map.get(taint_hit, f"'{taint_hit}'")
                desc = (
                    f"Data flow hazard: Untrusted data from {origin} propagates directly into "
                    f"security-sensitive sink '{call_name}()' without intermediate sanitization."
                )
                self.findings.append(Finding(
                    id=str(uuid.uuid4())[:8],
                    agent=AgentName.TAINT,
                    file=self.filename,
                    line=node.lineno,
                    rule_id=rule_id,
                    title=f"{title} ({call_name})",
                    description=desc,
                    severity=severity,
                    confidence=0.92,
                    cwe=cwe,
                    suggestion=suggestion,
                ))

        self.generic_visit(node)


class TaintAnalysisAgent:
    """Agent that traces data-flow paths from input sources to vulnerable sinks."""

    name = "taint_analysis"

    def analyze_file(self, source: SourceFile) -> List[Finding]:
        if not is_supported_source(source.path):
            return []
        if language_for(source.path) != "python":
            findings: List[Finding] = []
            for idx, line in enumerate(source.content.splitlines(), start=1):
                if re.search(r"\b(system|popen|execl|execv|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(", line):
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        agent=AgentName.TAINT,
                        file=source.path,
                        line=idx,
                        rule_id="TAINT-001",
                        title="Command Injection via External Input",
                        description="A command execution API is being used from a likely external input path and should be validated before use.",
                        severity=Severity.CRITICAL,
                        confidence=0.88,
                        cwe="CWE-78",
                        suggestion="Validate and sanitize user-controlled values, and avoid invoking shells when possible.",
                    ))
                if re.search(r"(?:executeQuery|execute\s*\(|PreparedStatement|SELECT\s+.*\+\s*\w+)", line, re.IGNORECASE):
                    findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        agent=AgentName.TAINT,
                        file=source.path,
                        line=idx,
                        rule_id="TAINT-003",
                        title="SQL Injection via Tainted Query Construction",
                        description="The SQL query appears built from variable input, which may be tainted and exploitable.",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        cwe="CWE-89",
                        suggestion="Use parameterized queries or prepared statements instead of string concatenation.",
                    ))
            return findings

        try:
            tree = ast.parse(source.content, filename=source.path)
        except SyntaxError:
            return []

        visitor = TaintVisitor(source.path)
        visitor.visit(tree)
        return visitor.findings

    def analyze(self, files: List[SourceFile]) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            findings.extend(self.analyze_file(f))
        return findings
