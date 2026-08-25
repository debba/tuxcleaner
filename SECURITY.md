# Security policy

TuxCleaner performs local maintenance operations, some of which permanently remove files or invoke privileged package-manager commands. Safety failures should be treated as security issues.

## Supported version

Only the latest release is supported while the project is in its initial development phase.

## Cleanup trust boundaries

TuxCleaner does not accept arbitrary cleanup commands. System actions are built by distribution adapters and must match an exact executable, argument list, and privilege requirement in the executor.

Filesystem removal is limited to known cache paths, individually selected large personal files, and exact project artifact directory names under the current user's canonical home directory. The executor rejects:

- root and the home directory itself
- relative paths and parent traversal
- anything outside the home directory
- `.git` at any path depth
- `.config`, `.ssh`, and `.gnupg`
- unknown directory names for cache and project cleanup
- personal-file paths containing hidden components or known developer-cache prefixes
- personal-file targets that are not regular files
- cleanup targets or ancestors that are symbolic links

Docker cleanup uses `docker system prune -f` without `--volumes`. TuxCleaner does not enumerate or remove Docker volumes.

Package cache cleanup is refused while a package transaction is running. A transaction installs archives straight out of the package caches, so emptying them mid-upgrade can fail the upgrade and leave the package database half written. On Arch systems the check is the presence of `/var/lib/pacman/db.lck`, which pacman creates for the duration of a transaction and removes afterwards. The apt and dnf lock files are permanent and held with `flock`, so their existence proves nothing and they are not used as a signal.

Large personal files found by `analyze` remain read-only unless `--remove` is passed. Interactive removal starts with an empty per-file selection and requires a final confirmation. Non-interactive removal requires both `--yes` and exact `--file` paths that appear in the current analysis. Hidden application data is never eligible.

## Application uninstall trust boundary

TuxCleaner lists only explicitly installed native packages that own visible desktop entries, plus Flatpak applications. Automated uninstall requires a source-qualified ID returned by the current catalog. The executor rejects malformed identifiers, mismatched IDs, protected system packages, and unexpected command shapes.

Native package managers must return a transaction preview before confirmation. A preview may include dependencies selected by the package manager, so users should review the full plan. TuxCleaner preserves application configuration and user data, including Flatpak data under `~/.var/app`.

## Privilege model

Package cache, native application uninstall, and journal cleanup use `sudo -- <program> <arguments>` when the process is not already running as root. User caches, developer caches, Docker, Flatpak, and project artifacts do not request privilege escalation.

Do not run the complete TuxCleaner process as root. Use the normal user account and allow the narrow `sudo` commands after reviewing the selected system group.

## History privacy and integrity

Operation history can contain local paths and package names. TuxCleaner creates its JSONL history and advisory lock files with owner-only permissions (`0600`). Existing history files are tightened to the same mode when opened. Concurrent readers and writers use the lock file, and bounded rotation occurs while holding an exclusive lock. Readers skip isolated malformed records rather than making the complete history unavailable.

## Reporting a vulnerability

Please open a private security advisory in the project repository. Include the affected version, exact command, distribution, expected safety boundary, and a minimal reproduction. Do not include personal file paths, credentials, or command history containing sensitive data.
