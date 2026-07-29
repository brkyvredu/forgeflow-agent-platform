import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PromptRisk:
    blocked: bool
    reasons: tuple[str, ...]


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(r"ignore (all|any|the) previous instructions", re.I)),
    ("secret_exfiltration", re.compile(r"(print|show|reveal|dump).*(secret|token|password|api key)", re.I)),
    ("unsafe_shell", re.compile(r"\b(rm\s+-rf|curl.+\|\s*(ba)?sh|powershell.+iex)\b", re.I)),
    ("path_escape", re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")),
)


def assess_prompt(text: str) -> PromptRisk:
    reasons = tuple(name for name, pattern in _PATTERNS if pattern.search(text))
    return PromptRisk(blocked=bool(reasons), reasons=reasons)


def enforce_safe_prompt(text: str) -> None:
    risk = assess_prompt(text)
    if risk.blocked:
        raise ValueError(f"Request rejected by policy: {', '.join(risk.reasons)}")
