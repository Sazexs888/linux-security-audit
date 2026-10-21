# Linux Security Audit & Remediation Tool v2.1.0

Read-only Linux security audit CLI written with the Python standard library. It checks file permissions, UID 0 accounts, empty password fields, listening ports, temporary files, SUID binaries, package updates, and selected SSH settings. Findings include severity, reason, and a suggested remediation command. The tool never executes remediation commands.

## Requirements

Python 3.10 or newer. No external packages are required.

## Usage

```bash
./linux-audit                 # interactive menu
./linux-audit --once          # one audit, no menu
./linux-audit --json          # JSON output
./linux-audit --self-test     # run the 10 built-in tests
sudo ./linux-audit --once     # include protected files such as /etc/shadow
```

The audit can also be started with `python3 audit_pro.py`. Logs are written to `~/.local/share/linux_audit/audit.log` by default. Override the path with `--log-file PATH`.

## Checks

| ID family | Check |
| --- | --- |
| `PERM-*` | Permissions on `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` |
| `USER-*`, `PASS-*` | Additional UID 0 accounts and empty password fields |
| `NET-*` | Listener inventory and selected risky ports |
| `TMP-*` | Executable and SUID/SGID files in temporary directories |
| `SUID-*` | SUID files outside the baseline and isolated Snap/container paths |
| `UPD-*` | Package update availability through apt, dnf, pacman, zypper, or apk |
| `SSH-*` | Root login and password authentication settings |

SUID findings outside the baseline need manual verification; they are not proof of compromise. Snap and container paths are classified as informational, not automatically trusted. The SUID scan traverses `/` and may take time on large or networked filesystems.

## Safety

The program only reads system state and writes its own log. Suggested shell commands are displayed for review and are never run by the tool. Use it only on systems you own or are authorized to audit.
