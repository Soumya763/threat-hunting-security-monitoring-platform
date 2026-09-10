"""
Detection rule loader.

Loads YAML threat-hunting rule files from threat_hunting_queries/templates/
and returns their parsed, validated content. This only loads rules — it
does not execute queries against Elasticsearch, schedule anything, or
generate alerts (those are separate, later stages).
"""

from pathlib import Path
from typing import Any

import yaml

# threat_hunting_queries/templates/ lives at the project root, three levels
# above this file: detection -> app -> backend -> <project root>.
DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "threat_hunting_queries" / "templates"
)

# Fields every rule YAML must define. Matches the schema used by
# threat_hunting_queries/templates/lateral_movement.yaml.
REQUIRED_FIELDS = [
    "name",
    "description",
    "mitre_tactic",
    "mitre_technique",
    "severity",
    "index",
    "query",
    "threshold",
]


class RuleValidationError(Exception):
    """Raised when a rule YAML file is malformed or missing required fields."""


def _validate_rule(rule: dict[str, Any], source_file: Path) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in rule]
    if missing:
        raise RuleValidationError(
            f"{source_file.name} is missing required field(s): {', '.join(missing)}"
        )


def load_rule_file(path: Path) -> dict[str, Any]:
    """Load, parse, and validate a single rule YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    if not isinstance(rule, dict):
        raise RuleValidationError(f"{path.name} does not contain a YAML mapping")

    _validate_rule(rule, path)

    return {field: rule[field] for field in REQUIRED_FIELDS}


def load_rules(rules_dir: Path | str = DEFAULT_RULES_DIR) -> list[dict[str, Any]]:
    """Load and validate every .yaml/.yml rule file found in rules_dir."""
    rules_dir = Path(rules_dir)

    rule_files = sorted(
        p for p in rules_dir.iterdir() if p.suffix.lower() in (".yaml", ".yml")
    )

    return [load_rule_file(path) for path in rule_files]


if __name__ == "__main__":
    for rule in load_rules():
        print(f"{rule['name']} | {rule['mitre_technique']} | severity={rule['severity']}")
