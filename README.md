# Linux Security Audit Tool

Read-only Linux security audit CLI written with the Python standard library.
It checks account and file permissions, listening ports, temporary files,
SUID binaries, package updates, and selected SSH settings. Findings include
severity, explanation, and suggested remediation commands. Commands are never
executed automatically.

## Run as a terminal application

Make the launcher executable once, then start the interactive menu:

```bash
chmod +x linux-audit
./linux-audit
```

The menu can start a full audit or the built-in self-tests and returns to the menu when finished. You can also run one-shot and automation modes directly:

```bash
python3 audit_pro.py --once
python3 audit_pro.py --json
python3 audit_pro.py --self-test
```

SUID discovery traverses `/` with `find`; it can take time on large filesystems.
Unusual SUID files are findings for manual review, not proof of compromise.
The scan uses a short baseline allowlist and may report legitimate vendor or
container packages. Package ownership hints use `dpkg -S` on apt-based systems
and `rpm -qf` elsewhere.
