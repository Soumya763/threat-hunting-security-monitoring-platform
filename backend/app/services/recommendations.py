"""
Analyst-facing recommendations, selected from the risk level and the evidence
actually present. Wording never says a file or URL is "safe".
"""


def _by_level(level: str) -> list[str]:
    return {
        "critical": [
            "Do not open, run or click this item. Quarantine it or block the source.",
            "Search internal telemetry for the same indicators (use the Log pivot) and check affected hosts.",
            "Open or link an incident and record the findings in its notes.",
        ],
        "high": [
            "Do not open, run or click this item until a second analyst has reviewed the findings.",
            "Run the local-context pivot to see whether other hosts or users encountered it.",
            "Consider linking this analysis to an incident.",
        ],
        "medium": [
            "Verify with the sender through a separate, trusted channel before any interaction.",
            "Review the static findings and matched rules before deciding.",
        ],
        "low": [
            "Low triage priority. Review the findings if the item was unexpected.",
        ],
        "clean": [
            "No consulted source flagged this item. This does not guarantee that it is safe.",
            "If the item was unexpected, verify the sender or source before trusting it.",
        ],
        "insufficient_evidence": [
            "There is not enough evidence to classify this item. Do not treat the absence of findings as safety.",
        ],
    }.get(level, [])


def recommend(level: str, *, providers_configured: bool, extension_mismatch: bool = False,
              detected_family: str | None = None, consent_available: bool = False,
              kind: str = "file") -> list[str]:
    actions = _by_level(level)
    if extension_mismatch and detected_family:
        actions.insert(0, f"The extension does not match the content ({detected_family}). Do not trust the file name.")
    if not providers_configured:
        actions.append("No external provider is configured. Add provider API keys in the backend environment to add reputation evidence.")
    if consent_available and level in ("insufficient_evidence", "medium"):
        if kind == "file":
            actions.append("If the file may be shared safely, you can submit it to VirusTotal with explicit consent (the file leaves this platform).")
        else:
            actions.append("You can submit this URL to urlscan.io with explicit consent (scans may be visible to others depending on visibility).")
    return actions
