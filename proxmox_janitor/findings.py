from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    key: str  # stable identity, used for notification dedupe and escalation fingerprints
    summary: str
    severity: str = "warning"  # info | warning | error
    escalate: bool = False  # True when the LLM should investigate
    once: bool = False  # notify once while the condition persists (e.g. forwarded notifications)
    details: dict[str, Any] = field(default_factory=dict)
    section: str = ""  # notification heading to file it under (default: by severity)
    line: str = ""  # markdown for notifications (default: summary)
