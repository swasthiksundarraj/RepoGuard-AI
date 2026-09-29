from __future__ import annotations

SUPPORTED_EXTENSIONS = {
    ".py",
    ".java",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
}

LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".java": "java",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hh": "cpp",
    ".hpp": "cpp",
}


def language_for(path: str) -> str | None:
    lower = path.lower()
    for ext, lang in LANGUAGE_BY_EXTENSION.items():
        if lower.endswith(ext):
            return lang
    return None


def is_supported_source(path: str) -> bool:
    return language_for(path) is not None
