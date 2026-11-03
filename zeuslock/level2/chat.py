"""Demo: a chat where the AI never sees the sensitive values.

    you type      -> anonymize -> sent to the AI (placeholders only)
    AI's reply    -> restore   -> what you see (real values back)

The "AI" here is the same local model (Ollama), so the demo runs offline.
"""

import requests

from zeuslock.core import llm
from zeuslock.level2.session import Session

ASSISTANT_PROMPT = (
    "You are a helpful assistant. Some values in the user's messages are replaced by "
    "placeholders like [EMAIL_1] or [CARD_1]. Keep using the placeholders exactly as written; "
    "never invent the real values. Answer briefly."
)


def ask_assistant(history: list[dict]) -> str:
    """Send the (anonymized) conversation to the local model, return its reply."""
    response = requests.post(
        f"{llm.OLLAMA_URL}/api/chat",
        json={
            "model": llm.MODEL,
            "messages": [{"role": "system", "content": ASSISTANT_PROMPT}] + history,
            "stream": False,
            "keep_alive": llm.KEEP_ALIVE,
        },
        timeout=llm.TIMEOUT_SECONDS * 2,
    )
    response.raise_for_status()
    return response.json()["message"]["content"]


def chat_turn(session: Session, history: list[dict], message: str, ask=ask_assistant) -> dict:
    """One message through the whole loop. Returns every stage, for display."""
    safe = session.anonymize(message)
    history.append({"role": "user", "content": safe})
    reply = ask(history)
    history.append({"role": "assistant", "content": reply})   # the AI's own words, placeholders kept
    return {"you": message, "sent": safe, "ai": reply, "shown": session.restore(reply)}


def print_turn(turn: dict) -> None:
    print(f"  sent to AI : {turn['sent']}")
    print(f"  AI wrote   : {turn['ai']}")
    print(f"  you see    : {turn['shown']}\n")


def run(messages: list[str] | None = None) -> None:
    """Interactive chat, or a scripted one when messages are given."""
    session, history = Session(), []
    if messages:
        for message in messages:
            print(f"you        : {message}")
            print_turn(chat_turn(session, history, message))
    else:
        print("Type a message (empty line to quit).\n")
        while message := input("you        : ").strip():
            print_turn(chat_turn(session, history, message))
    print(f"placeholders this session: {session.mapping}")
