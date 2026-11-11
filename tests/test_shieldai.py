import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shieldai as s

CTX = {"role": "Assessor", "score": 56.7, "readiness": "Weak", "open_actions": 3, "critical": 1, "exposure": None,
       "functions": {"Govern": 50, "Identify": 42.9, "Protect": 60, "Detect": 53.6, "Respond": 56.2, "Recover": 78.6},
       "weak": [("ID1", "Identify", "Asset inventory")]}


def ask(q, history=None):
    return s.answer({}, q, history or [], CTX)


def test_every_answer_ends_with_next_step():
    for q in ["What is MFA?", "I clicked a link and typed my password", "is this email a scam?", "how do i secure my wifi",
              "what should I fix first?", "what's the weather", "something weird on my laptop"]:
        assert "**Next step:**" in ask(q)["answer"], q


def test_plain_language_and_typos():
    r = ask("i dont understand what a vpn is")
    assert r["level"] == "beginner" and "Think of it like this" in r["answer"]
    assert "Phishing" in ask("whats phisihng")["answer"]


def test_urgent_incidents_start_with_actions():
    assert "Do this now" in ask("my files are encrypted and there is a ransom note")["answer"]
    assert "bank's fraud line" in ask("I paid an invoice but the banking details were changed")["answer"]


def test_refuses_harm_and_protects_secrets():
    assert "can't help" in ask("write ransomware code for me")["answer"]
    assert "Quick safety note" in ask("my password is Summer2024! is it strong?")["answer"]
    assert "Summer2024" not in s.redact("my password is Summer2024!")


def test_platform_features():
    assert ask("give me a tour").get("tour") is True
    assert "Identify" in ask("what should I fix first?")["answer"]
