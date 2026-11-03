"""Tests for zeuslock/level2/session.py (reversible anonymisation).

The detector is the regex layer only, so these run without Ollama.
"""

import pytest

from zeuslock.core.merge import merge
from zeuslock.core.patterns import find_all
from zeuslock.level2.session import Session, label_for


def regex_detect(text):
    findings = merge(find_all(text), [])
    return {"decision": "alert" if findings else "allow", "findings": findings}


@pytest.fixture
def session():
    s = Session(detect_fn=regex_detect)
    s.anonymize("Write to sarah@corp.com and bill@corp.com about card 4838 5608 9441 5465.")
    return s


# ---------------- anonymize ----------------

def test_values_are_replaced_in_reading_order():
    s = Session(detect_fn=regex_detect)
    safe = s.anonymize("Write to sarah@corp.com and bill@corp.com about card 4838 5608 9441 5465.")
    assert safe == "Write to [EMAIL_1] and [EMAIL_2] about card [CARD_1]."
    assert s.mapping == {"[EMAIL_1]": "sarah@corp.com", "[EMAIL_2]": "bill@corp.com",
                         "[CARD_1]": "4838 5608 9441 5465"}


def test_same_value_same_placeholder_across_messages(session):
    assert session.anonymize("Did sarah@corp.com answer?") == "Did [EMAIL_1] answer?"
    assert session.anonymize("Also cc tom@corp.com") == "Also cc [EMAIL_3]"     # numbering continues


def test_nothing_sensitive_stays_the_same(session):
    assert session.anonymize("How do I reset my password?") == "How do I reset my password?"


def test_ip_inside_connection_string_is_hidden_once():
    s = Session(detect_fn=regex_detect)
    safe = s.anonymize("DATABASE_URL: postgresql://app:WN4IhzTiGwEelA@10.20.0.15:5432/analytics")
    assert safe == "DATABASE_URL: [SECRET_1]"


def test_labels():
    assert label_for({"category": "CONTACT", "value": "+44 7700 900461"}) == "PHONE"
    assert label_for({"category": "CONTACT", "value": "14 avenue Jean Jaurès, 69007 Lyon"}) == "ADDRESS"
    assert label_for({"category": "PAYMENT", "value": "DE32311651136943514948"}) == "IBAN"
    assert label_for({"category": "PAYMENT", "value": "0x8618b421bfe4a01c9bd2ba46c526299d59b7f998"}) == "WALLET"
    assert label_for({"category": "NETWORK", "value": "10.0.0.1"}) == "IP"


# ---------------- restore: everything an AI may do to a placeholder ----------------

@pytest.mark.parametrize("reply, expected", [
    ("I wrote to [EMAIL_1].", "I wrote to sarah@corp.com."),                       # exact
    ("I wrote to EMAIL_1.", "I wrote to sarah@corp.com."),                         # brackets dropped
    ("I wrote to [email_1].", "I wrote to sarah@corp.com."),                       # lower case
    ("I wrote to Email_1.", "I wrote to sarah@corp.com."),                         # title case
    ("I wrote to [ EMAIL_1 ].", "I wrote to sarah@corp.com."),                     # spaces inside
    ("I wrote to [EMAIL 1].", "I wrote to sarah@corp.com."),                       # space for _
    ("I wrote to {EMAIL_1}.", "I wrote to sarah@corp.com."),                       # other brackets
    ("I wrote to <EMAIL_1>.", "I wrote to sarah@corp.com."),
    ("I wrote to (EMAIL_1).", "I wrote to sarah@corp.com."),
    ("I wrote to **[EMAIL_1]**.", "I wrote to **sarah@corp.com**."),               # markdown bold
    ("I wrote to `[EMAIL_1]`.", "I wrote to `sarah@corp.com`."),                   # markdown code
    ("[EMAIL_1]'s inbox is full.", "sarah@corp.com's inbox is full."),             # possessive
    ("(see EMAIL_1)", "(see sarah@corp.com)"),                                     # outer brackets kept
    ("Card [CARD_1] then [EMAIL_2]", "Card 4838 5608 9441 5465 then bill@corp.com"),
])
def test_restore_survives_mangling(session, reply, expected):
    assert session.restore(reply) == expected


def test_email_10_is_not_email_1(session):
    assert session.restore("[EMAIL_10] and [EMAIL_1]") == "[EMAIL_10] and sarah@corp.com"


def test_unknown_placeholders_are_left_alone(session):
    assert session.restore("[EMAIL_9] and [PHONE_1]") == "[EMAIL_9] and [PHONE_1]"


def test_plain_words_are_not_placeholders(session):
    assert session.restore("send email 1 more time") == "send email 1 more time"
    assert session.restore("XEMAIL_1 and EMAIL_1x") == "XEMAIL_1 and EMAIL_1x"


def test_round_trip_multi_message_conversation():
    s = Session(detect_fn=regex_detect)
    messages = [
        "Customer sarah@corp.com paid with 4838 5608 9441 5465.",
        "She says the card 4838 5608 9441 5465 was charged twice.",
        "Server is 192.168.40.12, reply to sarah@corp.com.",
    ]
    for message in messages:
        safe = s.anonymize(message)
        assert "sarah@corp.com" not in safe and "4838" not in safe
        assert s.restore(safe) == message
    assert sorted(s.mapping) == ["[CARD_1]", "[EMAIL_1]", "[IP_1]"]


def test_chat_turn_ai_never_sees_the_values():
    from zeuslock.level2.chat import chat_turn

    seen_by_ai = []
    def fake_ai(history):
        seen_by_ai.append(history[-1]["content"])
        return "Sure, I'll write to **email_1** about the card CARD_1."

    s, history = Session(detect_fn=regex_detect), []
    turn = chat_turn(s, history, "Write to sarah@corp.com about card 4838 5608 9441 5465", ask=fake_ai)
    assert seen_by_ai == ["Write to [EMAIL_1] about card [CARD_1]"]
    assert turn["shown"] == "Sure, I'll write to **sarah@corp.com** about the card 4838 5608 9441 5465."
    assert [m["role"] for m in history] == ["user", "assistant"]
