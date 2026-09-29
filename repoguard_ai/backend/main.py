"""
RepoGuard AI - FastAPI backend
--------------------------------
Exposes the multi-agent pipeline described in the paper as a small
HTTP API, and serves the static frontend dashboard from the same
process for a single-command demo (`uvicorn main:app`).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from models import AnalyzeRequest, AnalyzeResponse, SourceFile
from orchestrator import Orchestrator

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
SPEC_PATH = BASE_DIR / "default_spec.json"

app = FastAPI(title="RepoGuard AI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_current_spec = json.loads(SPEC_PATH.read_text())

MAX_FILES = 200
MAX_FILE_BYTES = 300_000


@app.get("/api/spec")
def get_spec():
    return _current_spec


@app.post("/api/spec")
def update_spec(new_spec: dict):
    _current_spec.update(new_spec)
    return _current_spec


@app.post("/api/spec/reset")
def reset_spec():
    global _current_spec
    _current_spec = json.loads(SPEC_PATH.read_text())
    return _current_spec


def _validate_files(files: List[SourceFile]):
    if not files:
        raise HTTPException(400, "No files were submitted for analysis.")
    if len(files) > MAX_FILES:
        raise HTTPException(400, f"Too many files (limit is {MAX_FILES}).")
    for f in files:
        if len(f.content.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
            raise HTTPException(400, f"File '{f.path}' exceeds the {MAX_FILE_BYTES}-byte limit.")


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    _validate_files(request.files)
    orchestrator = Orchestrator(
        files=request.files,
        spec=_current_spec,
        alpha=request.alpha,
        beta=request.beta,
        use_llm=request.use_llm,
        llm_provider=request.llm_provider,
        ollama_model=request.ollama_model,
    )
    result = orchestrator.run()
    return AnalyzeResponse(**result)


@app.get("/api/health")
def health():
    return {"status": "ok", "llm_configured": bool(os.environ.get("ANTHROPIC_API_KEY"))}


# Serve the frontend last so /api/* routes above take precedence.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
