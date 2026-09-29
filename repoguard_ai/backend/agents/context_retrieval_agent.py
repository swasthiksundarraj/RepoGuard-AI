"""
Context Retrieval Agent
------------------------
Implements the paper's "Context Retrieval Agent" (Section III-B): a
lightweight Retrieval-Augmented Generation (RAG) mechanism that indexes
every file in the submitted repository and, for a given target file,
retrieves the most relevant other files using vector similarity.

A dependency-free TF-IDF + cosine-similarity implementation is used so
the agent runs the same way with or without optional ML libraries
installed, keeping the reference implementation reproducible.
"""
from __future__ import annotations

import ast
import math
import re
from collections import Counter
from typing import Dict, List

from models import ContextSnippet, SourceFile

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def _extract_symbols(code: str) -> List[str]:
    try:
        tree = ast.parse(code)
        symbols = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols.append(node.name)
        return symbols
    except Exception:
        return []


class ContextRetrievalAgent:
    """Indexes a repository, extracts symbol graphs, and retrieves relevant context per file."""

    name = "context_retrieval"

    def __init__(self, files: List[SourceFile]):
        self.files = files
        self._doc_tokens: Dict[str, List[str]] = {
            f.path: _tokenize(f.content) for f in files
        }
        self._symbols: Dict[str, List[str]] = {
            f.path: _extract_symbols(f.content) for f in files
        }
        self._tf: Dict[str, Counter] = {
            path: Counter(tokens) for path, tokens in self._doc_tokens.items()
        }
        self._df: Counter = Counter()
        for tokens in self._doc_tokens.values():
            self._df.update(set(tokens))
        self._n_docs = max(len(files), 1)

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        return math.log((self._n_docs + 1) / (df + 1)) + 1.0

    def _vector(self, path: str) -> Dict[str, float]:
        tf = self._tf.get(path, Counter())
        total = sum(tf.values()) or 1
        return {term: (count / total) * self._idf(term) for term, count in tf.items()}

    @staticmethod
    def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        shared = set(a) & set(b)
        dot = sum(a[t] * b[t] for t in shared)
        norm_a = math.sqrt(sum(v * v for v in a.values()))
        norm_b = math.sqrt(sum(v * v for v in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def index(self) -> Dict[str, any]:
        """Return a summary of the built index including AST symbol graph."""
        total_symbols = sum(len(s) for s in self._symbols.values())
        return {
            "files_indexed": len(self.files),
            "vocabulary_size": len(self._df),
            "symbols_indexed": total_symbols,
            "symbols_per_file": self._symbols,
        }

    def retrieve(self, target_path: str, top_k: int = 3) -> List[ContextSnippet]:
        """Retrieve the top_k most relevant OTHER files for target_path."""
        target_vec = self._vector(target_path)
        target_tokens = set(self._doc_tokens.get(target_path, []))
        scored = []
        for f in self.files:
            if f.path == target_path:
                continue
            cos_score = self._cosine(target_vec, self._vector(f.path))
            
            # Boost score if target file references symbols declared in file f
            f_symbols = set(self._symbols.get(f.path, []))
            symbol_overlap = target_tokens & {s.lower() for s in f_symbols}
            boost = 0.15 * len(symbol_overlap) if symbol_overlap else 0.0

            final_score = min(1.0, cos_score + boost)
            if final_score > 0:
                preview = f.content.strip().splitlines()
                preview_text = " ".join(preview[:3])[:160]
                if symbol_overlap:
                    preview_text = f"[Symbols: {', '.join(list(symbol_overlap)[:3])}] " + preview_text
                scored.append(ContextSnippet(file=f.path, score=round(final_score, 4), preview=preview_text))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:top_k]

    def retrieve_all(self, top_k: int = 3) -> Dict[str, List[ContextSnippet]]:
        return {f.path: self.retrieve(f.path, top_k=top_k) for f in self.files}
