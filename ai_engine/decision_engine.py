"""Rule-based recommendation engine with optional LLM augmentation hook."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ai_engine.cve_mapper import ServiceCVEs
from ai_engine.rules import DEFAULT_RULES, Recommendation
from scanner.service_detector import DetectedService
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ServicePlan:
    service: DetectedService
    recommendations: List[Recommendation]
    cve_count: int


def _service_key(svc: DetectedService) -> str | None:
    name = (svc.name or "").lower()
    if not name:
        return None
    if name in DEFAULT_RULES:
        return name
    # Aliases
    aliases = {
        "https": "http",
        "http-proxy": "http",
        "ms-wbt-server": "rdp",
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "mysql": "mysql",
        "postgres": "postgresql",
    }
    return aliases.get(name)


def build_plan(mapped: list[ServiceCVEs]) -> list[ServicePlan]:
    """For each service, pick safe checks from the rule pack and rank by severity."""
    plans: list[ServicePlan] = []
    for entry in mapped:
        key = _service_key(entry.service)
        recs = list(DEFAULT_RULES.get(key, [])) if key else []

        # Boost rule severity if any related CVE is HIGH/CRITICAL.
        max_cvss = max((c.cvss or 0.0) for c in entry.cves) if entry.cves else 0.0
        if max_cvss >= 7.0:
            for rec in recs:
                if rec.severity_hint == "informational":
                    rec.severity_hint = "high"

        recs.sort(key=lambda r: _severity_rank(r.severity_hint), reverse=True)
        plans.append(
            ServicePlan(
                service=entry.service,
                recommendations=recs,
                cve_count=len(entry.cves),
            )
        )
    return plans


def _severity_rank(level: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}.get(
        level.lower(), 0
    )


def llm_augment(plans: list[ServicePlan], model: str | None = None) -> list[ServicePlan]:
    """Optional hook: use a local LLM to produce additional rationale.

    Disabled by default. To enable, install `transformers` and provide a model.
    The augmentation MUST NOT add modules outside the safe allowlist.
    """
    if not model:
        return plans
    try:
        # Lazy import - keeps this optional.
        from transformers import pipeline  # type: ignore

        pipe = pipeline("text-generation", model=model)
        for plan in plans:
            prompt = (
                "You are a defensive security analyst. Given the service "
                f"{plan.service.name} {plan.service.product or ''} "
                f"{plan.service.version or ''}, provide a one-sentence "
                "rationale for SAFE validation only."
            )
            generated = pipe(prompt, max_new_tokens=48, do_sample=False)[0][
                "generated_text"
            ]
            for rec in plan.recommendations:
                rec.rationale = f"{rec.rationale} | LLM: {generated.strip()[:200]}"
    except Exception as exc:  # pragma: no cover - best effort
        log.warning("LLM augmentation skipped: %s", exc)
    return plans
