"""Entry point imported by the graders.

    from submission import detect, Session
    detect("Can you check why my Visa 4838 5608 9441 5465 keeps getting declined?")

    session = Session()
    safe = session.anonymize("Mail sarah@corp.com")   # "Mail [EMAIL_1]"
    session.restore("Done, I wrote to [EMAIL_1].")     # "Done, I wrote to sarah@corp.com."
"""

from zeuslock.detector import detect
from zeuslock.level2.session import Session

__all__ = ["detect", "Session"]
