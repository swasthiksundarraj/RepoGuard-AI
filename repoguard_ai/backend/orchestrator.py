
"""
Orchestrator
-------------
Implements the paper's central Orchestrator (Section III-B / III-D):
schedules the specialized agents, merges their outputs

    F = F_s U F_m U F_sec

de-duplicates overlapping findings, and ranks the remainder using the
priority function

    P_i = alpha * S_i + beta * C_i

where S_i is severity (1-5) and C_i is confidence (0-1). Also times
each agent's execution to report the paper's "Agent Coordination
Overhead" metric, and computes the rest of the metric suite from
Section IV.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Tuple

from agents.context_retrieval_agent import ContextRetrievalAgent
from agents.security_agent import SecurityAssessmentAgent
from agents.semantic_review_agent import SemanticReviewAgent
from agents.static_analysis_agent import StaticAnalysisAgent
from agents.taint_analysis_agent import TaintAnalysisAgent
from code_cleaner import CodeCleaner
from models import AgentTiming, Finding, Metrics, SourceFile
from spec_checker import SpecificationChecker


class Orchestrator:
    """Coordinates all agents and produces the unified review report."""

    def __init__(self, files: List[SourceFile], spec: dict, alpha: float = 0.7,
                 beta: float = 0.3, use_llm: bool = False, llm_provider: str = "offline",
                 ollama_model: str = "deepseek-coder"):
        self.files = files
        self.spec = spec
        self.alpha = alpha
        self.beta = beta
        self.use_llm = use_llm
        self.llm_provider = llm_provider
        self.ollama_model = ollama_model
        self.timings: List[AgentTiming] = []

    def _timed(self, agent_name: str, fn, *args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.timings.append(AgentTiming(agent=agent_name, milliseconds=round(elapsed_ms, 3)))
        return result

    @staticmethod
    def _dedup_key(f: Finding) -> Tuple[str, int, str]:
        # Findings are considered duplicates if they land on (nearly) the
        # same file/line and reference the same underlying rule family.
        rule_family = f.rule_id.split("-")[0]
        return (f.file, f.line, rule_family)

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        best: Dict[Tuple[str, int, str], Finding] = {}
        for f in findings:
            key = self._dedup_key(f)
            existing = best.get(key)
            if existing is None or f.confidence > existing.confidence:
                best[key] = f
        return list(best.values())

    def _rank(self, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            f.priority = round(self.alpha * int(f.severity) + self.beta * f.confidence, 4)
        findings.sort(key=lambda f: f.priority, reverse=True)
        return findings

    def _compute_metrics(self, raw_count: int, findings: List[Finding], coord_overhead_ms: float) -> Metrics:
        by_agent = defaultdict(int)
        by_severity = defaultdict(int)
        for f in findings:
            by_agent[f.agent.value] += 1
            by_severity[str(int(f.severity))] += 1

        files_with_findings = len({f.file for f in findings})
        total_files = max(len(self.files), 1)
        coverage = round(100 * files_with_findings / total_files, 2)

        return Metrics(
            total_findings=len(findings),
            findings_by_agent=dict(by_agent),
            findings_by_severity=dict(by_severity),
            deduplicated_count=raw_count - len(findings),
            coverage_percent=coverage,
            coordination_overhead_ms=round(coord_overhead_ms, 3),
            hallucination_rate=None,  # requires human-labeled ground truth; not computable offline
            agent_timings=self.timings,
        )

    def run(self) -> dict:
        pipeline_start = time.perf_counter()

        context_agent = ContextRetrievalAgent(self.files)
        context_map = self._timed("context_retrieval", context_agent.retrieve_all)
        index_summary = context_agent.index()

        static_agent = StaticAnalysisAgent(self.spec)
        static_findings = self._timed("static_analysis", static_agent.analyze, self.files)

        semantic_agent = SemanticReviewAgent(use_llm=self.use_llm)
        semantic_findings = self._timed("semantic_review", semantic_agent.analyze, self.files, context_map)

        security_agent = SecurityAssessmentAgent()
        security_findings = self._timed("security_assessment", security_agent.analyze, self.files)

        taint_agent = TaintAnalysisAgent()
        taint_findings = self._timed("taint_analysis", taint_agent.analyze, self.files)

        spec_checker = SpecificationChecker(self.spec)
        spec_findings = self._timed("specification_checker", spec_checker.check_naming, self.files)

        all_findings = static_findings + semantic_findings + security_findings + taint_findings + spec_findings
        spec_checker.ground(all_findings)
        raw_count = len(all_findings)

        deduped = self._timed("orchestrator_dedup_rank", self._deduplicate, all_findings)
        ranked = self._rank(deduped)

        code_cleaner = CodeCleaner(
            use_llm=self.use_llm,
            spec=self.spec,
            llm_provider=self.llm_provider,
            ollama_model=self.ollama_model,
        )
        cleaned_files = self._timed("code_cleaner", code_cleaner.clean_files, self.files, ranked)

        coord_overhead_ms = (time.perf_counter() - pipeline_start) * 1000
        metrics = self._compute_metrics(raw_count, ranked, coord_overhead_ms)

        return {
            "findings": ranked,
            "context": {
                "index": index_summary,
                "per_file": {k: [s.dict() for s in v] for k, v in context_map.items()},
            },
            "metrics": metrics,
            "spec": self.spec,
            "cleaned_files": cleaned_files,
        }
