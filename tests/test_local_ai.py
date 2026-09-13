import pytest

from wwfi.ai import LocalPolicyAgent


def test_ai_rejects_untrusted_request():
    agent = LocalPolicyAgent()

    decision = agent.evaluate(identity="unknown", encrypted=False, risk_score=0.98)

    assert decision["allow"] is False
    assert decision["reason"] == "untrusted_or_unencrypted"


def test_ai_allows_safe_encrypted_request():
    agent = LocalPolicyAgent()

    decision = agent.evaluate(identity="alice", encrypted=True, risk_score=0.15)

    assert decision["allow"] is True
    assert decision["reason"] == "safe_local_policy"


def test_ai_scores_high_risk_requests():
    agent = LocalPolicyAgent()

    decision = agent.evaluate(identity="alice", encrypted=True, risk_score=0.91)

    assert decision["allow"] is False
    assert decision["reason"] == "risk_threshold_exceeded"
