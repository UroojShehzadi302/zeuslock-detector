"""Tests for zeuslock/core/validators.py, using values from the dev set."""

from zeuslock.core.validators import (
    iban_valid,
    is_private_ip,
    luhn_valid,
    nir_valid,
    ssn_valid,
)


def test_luhn_real_cards():
    assert luhn_valid("4838 5608 9441 5465")      # dev-001 Visa
    assert luhn_valid("5122210425786511")         # dev-002 Mastercard
    assert luhn_valid("3707-567293-46899")        # dev-003 Amex
    assert luhn_valid("4814235327619839")         # dev-035


def test_luhn_rejects_fake_numbers():
    assert not luhn_valid("4838 5608 9441 5468")  # dev-037: last digit changed
    assert not luhn_valid("4471-22-9038")         # dev-046 order number (too short)
    assert not luhn_valid("1234 5678 9012 3456")


def test_iban():
    assert iban_valid("FR22 2207 1247 9329 1173 1767 902")   # dev-004
    assert iban_valid("DE32311651136943514948")              # dev-005
    assert iban_valid("FR32 4965 0930 7859 8189 5437 077")   # dev-028
    assert not iban_valid("DE32311651136943514949")          # one digit changed


def test_nir():
    assert nir_valid("2 91 03 13 780 542 05")    # dev-025
    assert nir_valid("178112A25061988")          # dev-028 (Corsica, 2A)
    assert not nir_valid("2 91 03 13 780 542 06")


def test_ssn():
    assert ssn_valid("512-38-4417")              # dev-026
    assert not ssn_valid("000-12-3456")
    assert not ssn_valid("666-12-3456")


def test_private_ip():
    assert is_private_ip("192.168.40.12")        # dev-029
    assert is_private_ip("172.20.3.7")           # dev-030
    assert is_private_ip("10.20.0.15")           # dev-018
    assert not is_private_ip("1.1.1.1")          # dev-031: public resolver
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("999.1.1.1")        # not an IP
