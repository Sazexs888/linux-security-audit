# Linux Security Audit & Remediation Tool v2.2.0

Read-only Linux security audit CLI written with the Python standard library. Release 2.2.0 improves SSH configuration review, audit metadata, and log-file permissions. It checks file permissions, UID 0 accounts, empty password fields, listening ports, temporary files, SUID binaries, package updates, and selected SSH settings. Findings include severity, reason, and a suggested remediation command. The tool never executes remediation commands.

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

The audit can also be started with `python3 audit_pro.py`. New logs are created with owner-only permissions (`0600`). Existing log files with broader permissions and symbolic-link targets are refused without changing their permissions. Override the path with `--log-file PATH`.

## Checks

| ID family | Check |
| --- | --- |
| `PERM-*` | Permissions on `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` |
| `USER-*`, `PASS-*` | Additional UID 0 accounts and empty password fields |
| `NET-*` | Listener inventory and selected risky ports |
| `TMP-*` | Executable and SUID/SGID files in temporary directories |
| `SUID-*` | SUID files outside the baseline and isolated Snap/container paths |
| `UPD-*` | Package update availability through apt, dnf, pacman, zypper, or apk |
| `SSH-*` | Root login and password authentication settings, including `Include` files |

SUID findings outside the baseline need manual verification; they are not proof of compromise. Snap and container paths are classified as informational, not automatically trusted. The SUID scan searches the root filesystem only (`find -xdev`) and may take time on large installations.

SSH settings from `Include` files are included in the audit. Conditional `Match` blocks are reported for manual review because their effective values depend on connection details; inspect those with `sshd -T -C` for the relevant user and source address.

## Safety

The program does not change system security settings. It writes its own log; unsafe existing log targets are refused. Suggested shell commands are displayed for review and are never run by the tool. Use it only on systems you own or are authorized to audit.
