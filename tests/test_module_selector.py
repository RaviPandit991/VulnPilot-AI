"""Safety tests for the Metasploit module allowlist."""
from __future__ import annotations

from exploit_engine.module_selector import is_exploit_lab_safe, is_safe


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


# ---------------------------------------------------------------------------
# Lab-exploit gate (separate from the always-on safe-check gate)
# ---------------------------------------------------------------------------
def test_curated_lab_exploits_pass_lab_gate():
    assert is_exploit_lab_safe("exploit/unix/ftp/vsftpd_234_backdoor")
    assert is_exploit_lab_safe("exploit/unix/irc/unreal_ircd_3281_backdoor")
    assert is_exploit_lab_safe("exploit/unix/misc/distcc_exec")
    assert is_exploit_lab_safe("exploit/multi/samba/usermap_script")
    assert is_exploit_lab_safe("exploit/windows/smb/ms17_010_eternalblue")


def test_random_exploit_module_rejected_by_lab_gate():
    # Even though it starts with "exploit/", anything not in the curated
    # allowlist is rejected.
    assert not is_exploit_lab_safe("exploit/multi/handler")
    assert not is_exploit_lab_safe("exploit/windows/iis/some_overflow_thing")
    assert not is_exploit_lab_safe("exploit/some/random/module")


def test_dos_blocked_even_in_lab_gate():
    assert not is_exploit_lab_safe("auxiliary/dos/tcp/synflood")
    assert not is_exploit_lab_safe("exploit/dos/some_dos_thing")


def test_payload_and_post_blocked_in_lab_gate():
    """Bare payloads + post-exploitation modules must never auto-fire."""
    assert not is_exploit_lab_safe("payload/linux/x86/shell_reverse_tcp")
    assert not is_exploit_lab_safe("post/multi/manage/shell_to_meterpreter")


def test_overflow_blocked_in_lab_gate():
    assert not is_exploit_lab_safe("exploit/windows/smb/ms08_067_overflow")


def test_safe_check_modules_are_not_in_exploit_allowlist():
    """The two gates are separate: a safe-check module isn't auto-promoted
    into the exploit gate, and vice versa."""
    assert is_safe("auxiliary/scanner/ssh/ssh_version")
    assert not is_exploit_lab_safe("auxiliary/scanner/ssh/ssh_version")
    assert is_exploit_lab_safe("exploit/unix/ftp/vsftpd_234_backdoor")
    assert not is_safe("exploit/unix/ftp/vsftpd_234_backdoor")
