# Changelog

## 2.2.0 - 2026-10-22

### Added
- SSH audit now reads configuration files referenced through `Include`.
- System report includes whether the audit is running as root.

### Improved
- New audit log files are created with owner-only permissions (`0600`). Existing broad-permission files and symlink targets are refused without changing their permissions.
- SUID scanning stays on the root filesystem and uses a shorter timeout.
- Non-root and package-manager diagnostics explain permission and connectivity limitations more clearly.
- CLI warning specifies which checks may be limited without root access.

### Notes
- SUID findings still require manual verification; they are not proof of compromise.
- SSH configuration inside conditional `Match` blocks is reported for per-connection review; its values are not misclassified as global settings.
- The tool displays remediation suggestions but never executes them.
