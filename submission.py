"""Entry point imported by the graders.

    from submission import detect
    detect("Can you check why my Visa 4838 5608 9441 5465 keeps getting declined?")
"""

from zeuslock.detector import detect

__all__ = ["detect"]
