"""Safety tests for the Metasploit module allowlist."""
from __future__ import annotations

from exploit_engine.module_selector import is_safe


def test_allowlisted_aux_scanners_are_safe():
    assert is_safe("auxiliary/scanner/ssh/ssh_version")
    assert is_safe("auxiliary/scanner/smb/smb_ms17_010")
    assert is_safe("auxiliary/gather/enum_dns")
    assert is_safe("auxiliary/admin/http/iis_auth_bypass")


def test_exploit_modules_are_blocked():
    assert not is_safe("exploit/windows/smb/ms17_010_eternalblue")
    assert not is_safe("exploit/multi/handler")


def test_dos_modules_are_blocked():
    assert not is_safe("auxiliary/dos/tcp/synflood")


def test_post_and_payload_modules_are_blocked():
    assert not is_safe("post/multi/manage/shell_to_meterpreter")
    assert not is_safe("payload/windows/x64/meterpreter/reverse_tcp")


def test_overflow_modules_are_blocked():
    assert not is_safe("auxiliary/scanner/something_overflow")


def test_unknown_prefix_blocked():
    assert not is_safe("encoder/x86/shikata_ga_nai")
    assert not is_safe("/random/path")
    assert not is_safe("")
