from __future__ import annotations


class LocalPolicyAgent:
    def evaluate(self, *, identity: str | None, encrypted: bool, risk_score: float) -> dict:
        if not identity or not encrypted:
            return {"allow": False, "reason": "untrusted_or_unencrypted"}

        if risk_score > 0.8:
            return {"allow": False, "reason": "risk_threshold_exceeded"}

        if risk_score < 0.3:
            return {"allow": True, "reason": "safe_local_policy"}

        return {"allow": True, "reason": "moderate_local_policy"}
