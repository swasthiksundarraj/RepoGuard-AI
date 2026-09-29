# RepoGuard AI — Project Review

## 1. What this project does

This project is a full-stack code review and security analysis application for Python repositories and C-family/Java source files.
It accepts uploaded files or a sample repository, runs multiple analysis agents in parallel, combines their findings, ranks the issues by severity/confidence, and then shows a cleaned/remediated version of the code using a hybrid remediation gatekeeper.

The application is designed like a multi-agent review system:
- Static Analysis Agent checks syntax/AST and code quality rules.
- Semantic Review Agent checks maintainability/readability issues.
- Security Assessment Agent looks for CWE-based vulnerabilities.
- Taint Analysis Agent checks tainted data flow into dangerous sinks.
- Specification Checker validates naming and policy rules.
- Orchestrator merges and ranks the outputs.
- Code Cleaner generates safer alternatives and chooses the best one.

---

## 2. How the project works

### End-to-end flow

1. User uploads files or loads sample repo from the browser.
2. Frontend sends the files to the FastAPI backend via `/api/analyze`.
3. Backend creates an `Orchestrator` with the submitted files and project spec.
4. Orchestrator runs every analysis agent on the files.
5. All findings are deduplicated, ranked by priority, and summarized in metrics.
6. Code Cleaner runs both deterministic and neural remediation strategies.
7. A hybrid gatekeeper validates both outputs, scores them, and selects the best fix.
8. Frontend renders the findings, metrics, and cleaned code.

### AI workflow inside the project

The AI part is not a single monolithic model. It is a multi-stage workflow:

1. Retrieval step
   - `ContextRetrievalAgent` finds the most relevant files/snippets using repository context.
   - This helps the semantic reviewer work with project-level context instead of looking at one file alone.

2. Deterministic analysis stage
   - `StaticAnalysisAgent`, `SecurityAssessmentAgent`, and `TaintAnalysisAgent` inspect code through AST and rule-based logic.
   - These are explainable, repeatable, and do not require any external API.

3. LLM-assisted reasoning stage
   - `SemanticReviewAgent` can use the Anthropic API when `ANTHROPIC_API_KEY` is configured.
   - In this mode, it produces semantic findings using code context and repository similarity.
   - If no key is available, it falls back to deterministic heuristic checks.

4. Policy enforcement stage
   - `SpecificationChecker` validates findings against explicit project rules.
   - This adds a governance layer so the AI output is grounded in real project policies.

5. Multi-agent synthesis stage
   - The `Orchestrator` combines all outputs into one ranked report.
   - It deduplicates overlapping findings and prioritizes them with `P = α·S + β·C`.

6. Remediation gatekeeper stage
   - `CodeCleaner` generates both a deterministic fix and a neural/contextual fix.
   - It validates parse correctness, re-checks residual issues, scores each option, and selects the better one.

This is the key AI workflow pattern in the project: deterministic reasoning + contextual AI + validation gatekeeper.

---

## 3. File-by-file responsibilities

### Root project folder

- `README.md`
  - Project documentation.
  - Explains what is implemented, how to run it, and how to use the system.

- `frontend/`
  - The browser UI for the project.

- `sample_repo/`
  - A small intentionally vulnerable example repo used for testing/demo.

---

### Backend folder

- `backend/main.py`
  - FastAPI application entry point.
  - Defines API endpoints like:
    - `GET /api/spec`
    - `POST /api/spec`
    - `POST /api/analyze`
    - `GET /api/health`
  - Serves the frontend through static files.

- `backend/models.py`
  - Pydantic schema definitions.
  - Contains models like:
    - `SourceFile`
    - `Finding`
    - `Metrics`
    - `CleanedFile`
    - `AnalyzeRequest`
    - `AnalyzeResponse`
  - This is the shared contract between frontend, backend, and agents.

- `backend/orchestrator.py`
  - Main coordination engine.
  - Runs agents, merges their outputs, deduplicates findings, ranks them, and triggers code remediation.
  - Calculates summary metrics such as total findings, coverage, deduplication count, overhead, and agent timings.

- `backend/spec_checker.py`
  - Validates code and findings against project naming and policy rules from `default_spec.json`.
  - Marks findings as `spec_grounded` when they map directly to an explicit rule.

- `backend/default_spec.json`
  - Default project specification.
  - Stores rules like naming patterns, forbidden imports, and forbidden function usage.

- `backend/code_cleaner.py`
  - Auto-remediation logic.
  - Contains the hybrid gatekeeper:
    - deterministic remediation path
    - neural/contextual remediation path
    - syntax validation and residual issue scan
    - score-based selection of the best candidate
  - This is the part that decides which cleaned version is ultimately used.

---

### Agent files

- `backend/agents/static_analysis_agent.py`
  - Deterministic AST-based analysis.
  - Checks things like:
    - function length
    - parameter count
    - missing docstrings
    - mutable defaults
    - bare `except`
    - wildcard imports
    - complexity
  - This is the structural quality checker.

- `backend/agents/security_agent.py`
  - Security vulnerability detection.
  - Flags issues like:
    - hardcoded secrets
    - SQL injection risks
    - weak hashing
    - dangerous shell execution
    - insecure deserialization
    - insecure randomness
  - Maps findings to CWE IDs.

- `backend/agents/semantic_review_agent.py`
  - Semantic/maintainability review.
  - Uses a heuristic fallback by default for offline operation.
  - Can use live Anthropic LLM when configured.
  - Detects issues like long lines, TODOs, magic numbers, nested logic, and non-descriptive names.

- `backend/agents/context_retrieval_agent.py`
  - Finds related code context across files.
  - Uses TF-IDF-style similarity to rank relevant files/snippets for semantic review.

- `backend/agents/taint_analysis_agent.py`
  - Data-flow analysis for tainted input.
  - Looks for dangerous sinks like:
    - `os.system`
    - `eval`
    - `exec`
    - `pickle.loads`
    - SQL execution patterns
  - Helps catch injection or arbitrary execution paths that are not obvious from surface syntax alone.

---

### Frontend files

- `frontend/index.html`
  - Page structure for the dashboard.
  - Includes upload buttons, pipeline display, metrics, findings, clean code tabs, and modal panels.

- `frontend/style.css`
  - UI styling for the dashboard.
  - Colors, cards, tabs, severity chips, and code viewer layout.

- `frontend/app.js`
  - Browser logic for:
    - loading files
    - uploading from sample repo or paste input
    - sending requests to the backend
    - displaying findings and metrics
    - rendering code remediation views
    - switching between strategy views (deterministic, neural, hybrid)

---

## 4. Local project application mapping

This is the practical “which file does what” view for local work:

- `backend/main.py` = API server and app entry point.
- `backend/orchestrator.py` = brain of the project; orchestrates all agents.
- `backend/models.py` = data contracts and schemas.
- `backend/spec_checker.py` = policy checker for naming and forbidden usage.
- `backend/default_spec.json` = rules configuration file.
- `backend/code_cleaner.py` = code repair + hybrid verification engine.
- `backend/agents/*.py` = specialized analysis modules.
- `frontend/index.html` = dashboard shell.
- `frontend/app.js` = interactive dashboard logic.
- `frontend/style.css` = dashboard styling.
- `sample_repo/` = demo vulnerable code repo.
- `README.md` = project explanation and usage guide.

---

## 5. Local run flow

To run it locally:

```bash
cd repoguard_ai/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then open:

```text
http://127.0.0.1:8000
```

---

## 6. Simple summary

If you want the shortest mental model:

- Frontend = user interface
- Backend API = request processing layer
- Orchestrator = project coordinator
- Agents = specialized code reviewers
- Spec checker = quality policy enforcement
- Code cleaner = secure remediation engine
- UI + API + orchestrator + agents together = the complete RepoGuard AI review system

This project is basically a real multi-agent repository review application, not just a mock demo.
