"""Normalisation pre-pass (Level 2): undo common tricks before scanning.

    "My card is ４８３８ ５６０８ ..."        full-width digits      -> "4838 5608 ..."
    "ghp_qlfd<zero-width space>zcc..."       invisible characters   -> removed
    "ѕk-proj-..." (Cyrillic ѕ)               look-alike letters     -> "sk-proj-..."
    "four eight three eight ..."             number words           -> "4 8 3 8 ..."
    "sarah [at] corp [dot] com"              spelled-out @ and .    -> "sarah@corp.com"
    "ip-10-0-3-17"                           IP in a hostname       -> "ip-10.0.3.17 "

The scanners run on the normalised text, but findings must point into the ORIGINAL
text (golden rule: text[start:end] == value). So for every normalised character we
remember which original characters produced it:

    starts[i] = first original index behind normalised char i
    ends[i]   = original index just after it

A finding [s, e) in the normalised text is [starts[s], ends[e - 1]) in the original.
"""

import re
import unicodedata

# Invisible characters people use to break up secrets.
ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}

# Cyrillic / Greek letters that look like Latin ones.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "Α": "A", "Β": "B", "Ε": "E",
    "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Χ": "X", "Υ": "Y",
})

# Digit words in the languages of the dev set.
NUMBER_WORDS = {
    "zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5",
    "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "zéro": "0", "un": "1", "deux": "2", "trois": "3", "quatre": "4", "cinq": "5",
    "sept": "7", "huit": "8", "neuf": "9",
    "cero": "0", "uno": "1", "dos": "2", "tres": "3", "cuatro": "4", "cinco": "5",
    "seis": "6", "siete": "7", "ocho": "8", "nueve": "9",
    "null": "0", "eins": "1", "zwei": "2", "drei": "3", "vier": "4", "fünf": "5",
    "sechs": "6", "sieben": "7", "acht": "8", "neun": "9",
}
# Longest first, so "seven" wins over "seis" prefixes and "eight" over "eins"...
_WORD = "|".join(sorted(map(re.escape, NUMBER_WORDS), key=len, reverse=True))
# A run of at least 4 digit words, spaced or glued: "four eight three eight", "onetwothreefour".
# (Fewer than 4 digits can't be anything sensitive, and "one" alone is just English.)
NUMBER_RUN = re.compile(rf"(?i)\b(?:(?:{_WORD})[\s-]*){{3,}}(?:{_WORD})\b")
ONE_WORD = re.compile(rf"(?i){_WORD}")

# "[at]", "(at)", "{at}", "<at>", " [ at ] " and the same for dot.
SPELLED_AT = re.compile(r"(?i)\s*[\[({<]\s*at\s*[\])}>]\s*")
SPELLED_DOT = re.compile(r"(?i)\s*[\[({<]\s*dot\s*[\])}>]\s*")

# Hostnames like ip-10-0-3-17 (AWS style): the dashes between the 4 numbers become dots.
IP_HOSTNAME = re.compile(r"(?i)\bip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\b")


class Normalized:
    """Normalised text + the map back to the original."""

    def __init__(self, original: str):
        self.original = original
        self.text = ""
        self.starts: list[int] = []
        self.ends: list[int] = []

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        return self.starts[start], self.ends[end - 1]


def _rebuild(norm: Normalized, pattern: re.Pattern, replace) -> Normalized:
    """Apply one regex replacement to norm.text, keeping the map to the original.

    Each match is replaced by replace(match); every new character points to the
    whole original span of the match.
    """
    out = Normalized(norm.original)
    pieces, starts, ends = [], [], []
    position = 0
    for match in pattern.finditer(norm.text):
        a, b = match.span()
        pieces.append(norm.text[position:a])
        starts += norm.starts[position:a]
        ends += norm.ends[position:a]
        new = replace(match)
        if b > a:
            orig_start, orig_end = norm.starts[a], norm.ends[b - 1]
            pieces.append(new)
            starts += [orig_start] * len(new)
            ends += [orig_end] * len(new)
        position = b
    pieces.append(norm.text[position:])
    starts += norm.starts[position:]
    ends += norm.ends[position:]
    out.text, out.starts, out.ends = "".join(pieces), starts, ends
    return out


def _digits_for_run(match: re.Match) -> str:
    """'four eight-three' -> '4 8-3': each word becomes its digit, separators stay."""
    return ONE_WORD.sub(lambda m: NUMBER_WORDS[m.group(0).lower()], match.group(0))


def normalize(text: str) -> Normalized:
    norm = Normalized(text)

    # 1. Character by character: NFKC (full-width -> ASCII), drop invisible chars, homoglyphs.
    pieces = []
    for index, char in enumerate(text):
        if char in ZERO_WIDTH:
            continue
        new = unicodedata.normalize("NFKC", char).translate(HOMOGLYPHS)
        pieces.append(new)
        norm.starts += [index] * len(new)
        norm.ends += [index + 1] * len(new)
    norm.text = "".join(pieces)

    # 2. Word-level tricks.
    norm = _rebuild(norm, NUMBER_RUN, _digits_for_run)
    norm = _rebuild(norm, SPELLED_AT, lambda m: "@")
    norm = _rebuild(norm, SPELLED_DOT, lambda m: ".")
    # The space ends the IP: in "ip-10-0-3-17.eu-west-3.compute" the next "." would otherwise
    # make it look like a longer dotted number, which the IP rule rejects on purpose.
    norm = _rebuild(norm, IP_HOSTNAME, lambda m: "ip-" + ".".join(m.groups()) + " ")
    return norm
