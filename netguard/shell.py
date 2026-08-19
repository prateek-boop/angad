"""
Direct-subprocess execution for Linux network commands.

Replaces the old Shizuku/ADB-shell bridge: netguard runs as a standalone
Linux service under its own privileges (typically root, or CAP_NET_ADMIN/
CAP_NET_RAW), so there is no privilege-elevation workaround to route
through — it calls iptables/ss directly.
"""

import logging
import subprocess

from . import constants

logger = logging.getLogger("NETGUARD.SHELL")

_ALLOWED_IPTABLES_OPS = ("-A", "-D", "-I", "-L", "-F", "-N", "-X", "-C")


def run(args: list[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run a command directly (no shell interpolation) and return (code, stdout, stderr)."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (result.returncode, result.stdout.strip(), result.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(args)}")
        return (-1, "", "Command timed out")
    except FileNotFoundError as e:
        logger.error(f"Command not found: {e}")
        return (-1, "", str(e))
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return (-1, "", str(e))


def run_iptables(args: list[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run iptables with an operation allowlist, mirroring the old Shizuku validation."""
    if not any(op in args for op in _ALLOWED_IPTABLES_OPS):
        return (-1, "", "Invalid iptables operation")
    return run([constants.IPTABLES_BIN, *args], timeout=timeout)


def run_ss(args: list[str] = ("-ntup",), timeout: int = 5) -> tuple[int, str, str]:
    """Run `ss` directly to dump socket state."""
    return run([constants.SS_BIN, *args], timeout=timeout)
