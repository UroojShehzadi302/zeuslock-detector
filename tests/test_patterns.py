"""Tests for zeuslock/core/patterns.py (the regex layer)."""

import json
from pathlib import Path

from zeuslock.core.patterns import find_all

DEV_SET = Path(__file__).parent.parent / "data" / "dev_set.jsonl"


def values(text):
    return {f["value"] for f in find_all(text)}


def test_offsets_always_match_value():
    """The golden rule: text[start:end] == value, for every dev prompt."""
    for line in DEV_SET.read_text(encoding="utf-8").splitlines():
        text = json.loads(line)["text"]
        for f in find_all(text):
            assert text[f["start"]:f["end"]] == f["value"]


def test_payment():
    assert "4838 5608 9441 5465" in values("my Visa 4838 5608 9441 5465 keeps failing")
    assert "FR22 2207 1247 9329 1173 1767 902" in values("IBAN : FR22 2207 1247 9329 1173 1767 902. Merci")
    assert "0x8618b421bfe4a01c9bd2ba46c526299d59b7f998" in values("wallet 0x8618b421bfe4a01c9bd2ba46c526299d59b7f998")


def test_credentials():
    assert "ghp_qlfdzccIxspgpXi7gehOkOPiFJ8o2zDUt4Ym" in values("token ghp_qlfdzccIxspgpXi7gehOkOPiFJ8o2zDUt4Ym in CI")
    assert "AKIANRCBDKPIFERSPSOC" in values("AWS_ACCESS_KEY_ID=AKIANRCBDKPIFERSPSOC")
    assert "Tr0ub4dor&3" in values("username=svc password=Tr0ub4dor&3 timeout=30")
    assert "Soleil-Marseille-2026" in values("Mot de passe du wifi invités : Soleil-Marseille-2026, merci")


def test_contact_and_gov_id():
    assert "sarah.okonkwo@brightwell-partners.co.uk" in values("reply to sarah.okonkwo@brightwell-partners.co.uk thanks")
    assert "+44 7700 900461" in values("call +44 7700 900461 please")
    assert "512-38-4417" in values("applicant SSN 512-38-4417, please")
    assert "19AV52310" in values("Numéro de passeport du consultant : 19AV52310, il part")


def test_network_private_only():
    assert "192.168.40.12" in values("db moved to 192.168.40.12, update it")
    assert values("Is 1.1.1.1 a good resolver?") == set()


def test_not_sensitive():
    """Things that look like data but are not sensitive."""
    assert values("How do I reset my password if I lost my email?") == set()
    assert values("replace YOUR_API_KEY_HERE with your own key") == set()
    assert values("El pedido número 4471-22-9038 salió ayer") == set()
    assert values("The ISBN of the handbook is 978-0-262-03384-8") == set()
    assert values("commit 4f9c2a17b3e85d6019ac7e4b2f81d5c60e93a7b4 broke the build") == set()
    assert values("Release v3.12.4-rc2 went out; p95 is 210 ms") == set()
    assert values("card number 4838 5608 9441 5468 is it a reference?") == set()  # fails Luhn
