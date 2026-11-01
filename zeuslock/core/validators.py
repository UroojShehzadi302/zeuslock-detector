"""Checks that a value which *looks* sensitive really is valid.

A regex only checks the shape of a value. These functions check the maths
(checksums) or the meaning (private vs public IP), which removes false alarms.
"""

import ipaddress


def only_digits(value: str) -> str:
    """Keep only the digits: '4838 5608-9441' -> '483856089441'."""
    return "".join(ch for ch in value if ch.isdigit())


def luhn_valid(number: str) -> bool:
    """Card number checksum (Luhn algorithm).

    From the right, double every second digit; if the result is > 9, subtract 9.
    Add everything up. A real card number gives a total divisible by 10.
    """
    digits = only_digits(number)
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    for position, ch in enumerate(reversed(digits)):
        digit = int(ch)
        if position % 2 == 1:      # every second digit from the right
            digit = digit * 2
            if digit > 9:
                digit = digit - 9
        total += digit
    return total % 10 == 0


def iban_valid(iban: str) -> bool:
    """IBAN checksum (ISO 13616, mod-97).

    1. Remove spaces, move the first 4 characters to the end.
    2. Replace each letter with a number (A=10, B=11, ... Z=35).
    3. The resulting big number mod 97 must equal 1.
    """
    iban = iban.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34:
        return False
    if not (iban[:2].isalpha() and iban[2:4].isdigit() and iban.isalnum()):
        return False

    rearranged = iban[4:] + iban[:4]
    as_number = ""
    for ch in rearranged:
        if ch.isdigit():
            as_number += ch
        else:
            as_number += str(ord(ch) - ord("A") + 10)
    return int(as_number) % 97 == 1


def nir_valid(nir: str) -> bool:
    """French social security number (NIR) checksum.

    Format: 13 characters + 2-digit key. Corsica uses '2A' / '2B' as the
    department, which are replaced by 19 / 18 before the maths.
    The key must equal 97 - (first 13 digits mod 97).
    """
    nir = nir.replace(" ", "").upper()
    if len(nir) != 15:
        return False

    body = nir[:13]
    key = nir[13:]
    body = body.replace("2A", "19").replace("2B", "18")
    if not (body.isdigit() and key.isdigit()):
        return False
    return 97 - (int(body) % 97) == int(key)


def ssn_valid(ssn: str) -> bool:
    """US social security number: basic rules from the SSA.

    Area (first 3) can't be 000, 666 or 900-999; group (middle 2) can't be 00;
    serial (last 4) can't be 0000.
    """
    digits = only_digits(ssn)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area == "000" or area == "666" or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def is_private_ip(value: str) -> bool:
    """True for internal addresses (10.x, 172.16-31.x, 192.168.x, 127.x ...).

    Public addresses like 1.1.1.1 or 8.8.8.8 are not sensitive, so they return False.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:          # not an IP at all, e.g. '999.1.1.1'
        return False
    return ip.is_private and not ip.is_unspecified
