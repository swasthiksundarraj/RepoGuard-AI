"""
Semantic Review Agent
------------------------
Implements the paper's "Semantic Review Agent" (Section III-B): uses a
Large Language Model as its primary reasoning model to analyze code
semantics, maintainability, readability, and design consistency, using
retrieved repository context to ground its comments.

Two execution modes are supported:

1. LLM mode (use_llm=True and ANTHROPIC_API_KEY is set): the agent
   calls the real Anthropic Messages API, passing the file content and
   the context snippets retrieved by the Context Retrieval Agent, and
   asks for STRUCTURED JSON findings. This is the mode described in
   the paper.

2. Heuristic fallback mode (default, no API key required): a
   deterministic, explainable heuristic reviewer that flags common
   maintainability smells (naming, nesting depth, long lines, magic
   numbers, TODOs). This keeps the reference implementation fully
   reproducible and runnable offline for grading/demo purposes, while
   the LLM hook shows the intended production path from the paper.
"""
from __future__ import annotations

import ast
import json
import os
import re
import uuid
from typing import List

from language_support import is_supported_source, language_for
from models import AgentName, ContextSnippet, Finding, Severity, SourceFile

MAGIC_NUMBER_RE = re.compile(r"(?<![\w.])(?!0\b|1\b)-?\d{2,}(?![\w])")
TODO_RE = re.compile(r"#\s*(TODO|FIXME|HACK)\b", re.IGNORECASE)


class SemanticReviewAgent:
    """LLM-based semantic reviewer with a deterministic heuristic fallback."""

    name = "semantic_review"

    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm and bool(os.environ.get("ANTHROPIC_API_KEY"))

    def _make(self, file, line, rule_id, title, desc, severity, confidence, suggestion=None) -> Finding:
        return Finding(
            id=str(uuid.uuid4())[:8],
            agent=AgentName.SEMANTIC,
            file=file,
            line=line,
            rule_id=rule_id,
            title=title,
            description=desc,
            severity=severity,
            confidence=confidence,
            suggestion=suggestion,
        )

    # ---------------------------------------------------------- heuristic
    def _heuristic_review(self, source: SourceFile, context: List[ContextSnippet]) -> List[Finding]:
        findings: List[Finding] = []
        if not is_supported_source(source.path):
            return findings
        lines = source.content.splitlines()

        for i, line in enumerate(lines, start=1):
            if len(line) > 100:
                findings.append(self._make(
                    source.path, i, "SR-001", "Long line",
                    f"Line exceeds 100 characters ({len(line)}), hurting readability.",
                    Severity.INFO, 0.5,
                    "Wrap or refactor the line to stay within the project's style guide.",
                ))
            if TODO_RE.search(line):
                findings.append(self._make(
                    source.path, i, "SR-002", "Unresolved TODO/FIXME",
                    "A TODO/FIXME comment suggests incomplete or provisional logic.",
                    Severity.LOW, 0.6,
                    "Resolve the outstanding task or file it as a tracked issue.",
                ))
            if MAGIC_NUMBER_RE.search(line) and "def " not in line and "#" not in line.split("=")[0]:
                findings.append(self._make(
                    source.path, i, "SR-003", "Magic number",
                    "A multi-digit literal appears inline without a named "
                    "constant, making its meaning unclear to future readers.",
                    Severity.INFO, 0.4,
                    "Extract the value into a well-named constant.",
                ))

        if language_for(source.path) != "python":
            if context:
                related = ", ".join(c.file for c in context[:2])
                findings.append(self._make(
                    source.path, 1, "SR-CTX", "Related repository context",
                    f"This file shares significant vocabulary with {related}; changes here may need corresponding updates there.",
                    Severity.INFO, 0.4,
                    "Cross-check related files before merging this change.",
                ))
            return findings

        try:
            tree = ast.parse(source.content, filename=source.path)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if len(node.name) <= 2 and not node.name.startswith("_"):
                    findings.append(self._make(
                        source.path, node.lineno, "SR-004", "Non-descriptive function name",
                        f"'{node.name}' is very short and does not clearly "
                        "communicate the function's purpose.",
                        Severity.INFO, 0.45,
                        "Rename to a descriptive, intention-revealing name.",
                    ))
                depth = self._max_nesting(node)
                if depth >= 4:
                    findings.append(self._make(
                        source.path, node.lineno, "SR-005", "Deep nesting",
                        f"'{node.name}' has a nesting depth of {depth}, which "
                        "increases cognitive load and risk of logic errors.",
                        Severity.MEDIUM, 0.6,
                        "Use guard clauses or extract nested blocks into helper functions.",
                    ))

        if context:
            related = ", ".join(c.file for c in context[:2])
            findings.append(self._make(
                source.path, 1, "SR-CTX", "Related repository context",
                f"This file shares significant vocabulary with {related}; "
                "changes here may need corresponding updates there.",
                Severity.INFO, 0.4,
                "Cross-check related files before merging this change.",
            ))

        return findings

    @staticmethod
    def _max_nesting(node: ast.AST, depth: int = 0) -> int:
        nested = (ast.If, ast.For, ast.While, ast.Try, ast.With)
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, nested):
                max_depth = max(max_depth, SemanticReviewAgent._max_nesting(child, depth + 1))
            else:
                max_depth = max(max_depth, SemanticReviewAgent._max_nesting(child, depth))
        return max_depth

    # ---------------------------------------------------------------- LLM
    def _llm_review(self, source: SourceFile, context: List[ContextSnippet]) -> List[Finding]:
        try:
            import anthropic
        except ImportError:
            return self._heuristic_review(source, context)

        client = anthropic.Anthropic()
        context_text = "\n".join(f"- {c.file}: {c.preview}" for c in context) or "(no related files found)"
        prompt = f"""You are a senior software engineer performing semantic code review.
Review the following file for maintainability, readability, design, and logic issues.
Ground your comments in the retrieved repository context below when relevant.

Related repository context:
{context_text}

File: {source.path}
```
{source.content[:6000]}
```

Respond with ONLY a JSON array (no prose, no markdown fences). Each element must have:
"line" (int), "title" (string), "description" (string), "severity" (one of 1,2,3,4,5 where 5 is most severe),
"confidence" (float 0-1), "suggestion" (string).
Return at most 8 findings. If there are no issues, return []."""

        try:
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in response.content if block.type == "text")
            text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            items = json.loads(text)
        except Exception as exc:  # network/parse failure -> degrade gracefully
            fallback = self._heuristic_review(source, context)
            fallback.append(self._make(
                source.path, 0, "SR-LLM-ERR", "LLM review unavailable",
                f"Falling back to heuristic review because the LLM call "
                f"failed: {exc}",
                Severity.INFO, 0.3,
            ))
            return fallback

        findings: List[Finding] = []
        for item in items:
            findings.append(self._make(
                source.path,
                int(item.get("line", 0) or 0),
                "SR-LLM",
                str(item.get("title", "Semantic finding"))[:120],
                str(item.get("description", ""))[:600],
                Severity(int(item.get("severity", 2))),
                float(item.get("confidence", 0.6)),
                item.get("suggestion"),
            ))
        return findings

    # ------------------------------------------------------------- public
    def analyze(self, files: List[SourceFile], context_map: dict) -> List[Finding]:
        findings: List[Finding] = []
        for f in files:
            ctx = context_map.get(f.path, [])
            if self.use_llm:
                findings.extend(self._llm_review(f, ctx))
            else:
                findings.extend(self._heuristic_review(f, ctx))
        return findings
