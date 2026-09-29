"""
Security Assessment Agent
---------------------------
Implements the paper's "Security Assessment Agent" (Section III-B):
identifies vulnerability classes such as injection, insecure
deserialization, weak cryptography, and hardcoded secrets, and grounds
each finding in Common Weakness Enumeration (CWE) identifiers.

Detection combines AST inspection (for call-based patterns, which is
robust to formatting) with targeted regular expressions (for patterns
such as hardcoded secrets that are easier to express lexically). This
mirrors the paper's description of "LLM-based security reasoning
together with security knowledge derived from vulnerability
taxonomies" -- here the taxonomy lookup (CWE mapping) is deterministic,
while the pattern set stands in for the reasoning step so the agent is
fully reproducible without external API calls.
"""
from __future__ import annotations

import ast
import re
import uuid
from typing import List

from language_support import is_supported_source, language_for
from models import AgentName, Finding, Severity, SourceFile

SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|apikey|token|access_key)\s*=\s*"
    r"['\"][^'\"\s]{4,}['\"]"
)

DANGEROUS_CALLS = {
    "eval": ("SEC-001", "Use of eval()", "CWE-95",
              "eval() executes arbitrary strings as code and is a common "
              "code-injection vector.", Severity.CRITICAL, 0.9,
              "Avoid eval(); use ast.literal_eval() for data, or a safe parser."),
    "exec": ("SEC-002", "Use of exec()", "CWE-95",
              "exec() executes arbitrary strings as code and can allow "
              "arbitrary code execution if input is not fully trusted.",
              Severity.CRITICAL, 0.9,
              "Avoid exec(); redesign to avoid dynamic code execution."),
    "pickle.loads": ("SEC-003", "Insecure deserialization", "CWE-502",
              "pickle.loads() on untrusted data can execute arbitrary code "
              "during deserialization.", Severity.HIGH, 0.85,
              "Use a safe serialization format such as JSON, or validate the source."),
    "yaml.load": ("SEC-004", "Unsafe YAML load", "CWE-502",
              "yaml.load() without a safe loader can instantiate arbitrary "
              "Python objects from untrusted input.", Severity.HIGH, 0.8,
              "Use yaml.safe_load() instead of yaml.load()."),
    "os.system": ("SEC-005", "Shell command execution", "CWE-78",
              "os.system() passes input to a shell, risking OS command "
              "injection if any part of the command is user-controlled.",
              Severity.HIGH, 0.75,
              "Use subprocess.run([...], shell=False) with a list of arguments."),
    "random.random": ("SEC-006", "Non-cryptographic randomness", "CWE-330",
              "The 'random' module is not cryptographically secure and "
              "should not be used for tokens, passwords, or keys.",
              Severity.MEDIUM, 0.55,
              "Use the 'secrets' module for security-sensitive randomness."),
}

HASH_FUNCS = {"md5", "sha1"}


class SecurityAssessmentAgent:
    """Detects common vulnerability classes with CWE grounding."""

    name = "security_assessment"

    def _make(self, file, line, rule_id, title, desc, severity, confidence, cwe, suggestion) -> Finding:
        return Finding(
            id=str(uuid.uuid4())[:8],
            agent=AgentName.SECURITY,
            file=file,
            line=line,
            rule_id=rule_id,
            title=title,
            description=desc,
            severity=severity,
            confidence=confidence,
            cwe=cwe,
            suggestion=suggestion,
        )

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

    def analyze_file(self, source: SourceFile) -> List[Finding]:
        findings: List[Finding] = []
        if not is_supported_source(source.path):
            return findings

        if language_for(source.path) == "python":
            for match in SECRET_PATTERN.finditer(source.content):
                line = source.content.count("\n", 0, match.start()) + 1
                findings.append(self._make(
                    source.path, line, "SEC-000", "Hardcoded credential",
                    "A password, API key, or token appears to be hardcoded "
                    "directly in source code, where it can leak via version control.",
                    Severity.CRITICAL, 0.7, "CWE-798",
                    "Load secrets from environment variables or a secrets manager.",
                ))

            if "shell=True" in source.content:
                line = next((i + 1 for i, l in enumerate(source.content.splitlines()) if "shell=True" in l), 0)
                findings.append(self._make(
                    source.path, line, "SEC-007", "Shell injection risk",
                    "subprocess called with shell=True can allow command "
                    "injection if any argument is influenced by user input.",
                    Severity.HIGH, 0.7, "CWE-78",
                    "Call subprocess with shell=False and pass arguments as a list.",
                ))

            try:
                tree = ast.parse(source.content, filename=source.path)
            except SyntaxError:
                return findings

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = self._call_name(node)
                    if name in DANGEROUS_CALLS:
                        rule_id, title, cwe, desc, sev, conf, suggestion = DANGEROUS_CALLS[name]
                        findings.append(self._make(
                            source.path, node.lineno, rule_id, title, desc, sev, conf, cwe, suggestion,
                        ))
                    elif name in ("hashlib.new",) and node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.lower() in HASH_FUNCS:
                            findings.append(self._make(
                                source.path, node.lineno, "SEC-008", "Weak hash algorithm",
                                f"'{arg.value}' is a cryptographically broken hash "
                                "algorithm and should not be used for security purposes.",
                                Severity.MEDIUM, 0.75, "CWE-327",
                                "Use hashlib.sha256() or a dedicated password-hashing function (e.g. bcrypt/argon2).",
                            ))
                    elif name.startswith("hashlib.") and name.split(".")[1] in HASH_FUNCS:
                        findings.append(self._make(
                            source.path, node.lineno, "SEC-008", "Weak hash algorithm",
                            f"'{name}' is a cryptographically broken hash algorithm "
                            "and should not be used for security purposes.",
                            Severity.MEDIUM, 0.75, "CWE-327",
                            "Use hashlib.sha256() or a dedicated password-hashing function (e.g. bcrypt/argon2).",
                        ))

                if isinstance(node, ast.Call):
                    name = self._call_name(node)
                    if name.endswith(".execute") and node.args:
                        arg = node.args[0]
                        if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                            findings.append(self._make(
                                source.path, node.lineno, "SEC-009", "Possible SQL injection",
                                "A SQL query appears to be built via string "
                                "concatenation or an f-string rather than "
                                "parameterized query placeholders.",
                                Severity.CRITICAL, 0.65, "CWE-89",
                                "Use parameterized queries, e.g. cursor.execute(query, params).",
                            ))
            return findings

        for idx, line in enumerate(source.content.splitlines(), start=1):
            if re.search(r"(?i)(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*(=|:)\s*[\"'][^\"']+[\"']", line):
                findings.append(self._make(
                    source.path, idx, "SEC-000", "Hardcoded credential",
                    "A credential appears hardcoded in the source tree and could be exposed in version control.",
                    Severity.CRITICAL, 0.7, "CWE-798",
                    "Load this value from an environment variable or secrets manager.",
                ))
            if re.search(r"\b(system|popen|execl|execv|CreateProcess|ProcessBuilder|Runtime\.getRuntime\(\)\.exec)\s*\(", line):
                findings.append(self._make(
                    source.path, idx, "SEC-005", "Shell command execution",
                    "A command is being executed from a string, which risks command injection or unsafe shell invocation.",
                    Severity.HIGH, 0.8, "CWE-78",
                    "Pass a validated argument list without invoking a shell or use a safe API.",
                ))
            if re.search(r"\b(gets|strcpy|strcat|sprintf|scanf)\s*\(", line):
                findings.append(self._make(
                    source.path, idx, "SEC-011", "Unsafe buffer operation",
                    "This call is prone to buffer overflow or unsafe memory handling.",
                    Severity.HIGH, 0.75, "CWE-120",
                    "Replace it with bounded APIs and explicit length checks.",
                ))
            if re.search(r"\b(md5|sha1|MessageDigest\.getInstance\(\s*[\"']MD5|MessageDigest\.getInstance\(\s*[\"']SHA-1|hashlib\.md5|hashlib\.sha1)\b", line, re.IGNORECASE):
                findings.append(self._make(
                    source.path, idx, "SEC-008", "Weak hash algorithm",
                    "A weak or obsolete hashing algorithm is in use for security-sensitive data.",
                    Severity.MEDIUM, 0.75, "CWE-327",
                    "Use SHA-256 or stronger algorithms, or a dedicated password hashing function.",
                ))
            if re.search(r"\b(rand\s*\(|random\s*\(|Math\.random\s*\()", line):
                findings.append(self._make(
                    source.path, idx, "SEC-006", "Non-cryptographic randomness",
                    "The code uses a non-cryptographic random source where a secure token or secret is required.",
                    Severity.MEDIUM, 0.6, "CWE-330",
                    "Use a cryptographic RNG such as a secure library or OS PRNG.",
                ))
            if re.search(r"(?:executeQuery|execute\s*\(|PreparedStatement|sprintf\s*\([^\n]*SELECT|SELECT\s+.*\+\s*\w+)", line, re.IGNORECASE):
                findings.append(self._make(
                    source.path, idx, "SEC-009", "Possible SQL injection",
                    "A query appears to be assembled from variable input, which risks SQL injection.",
                    Severity.CRITICAL, 0.7, "CWE-89",
                    "Use parameterized queries or prepared statements instead of string concatenation.",
                ))

        return findings

    def analyze(self, files: List[SourceFile]) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            findings.extend(self.analyze_file(f))
        return findings
