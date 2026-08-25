# Architecture

## Design goals

TuxCleaner keeps scanning, policy, and execution separate. A scanner may discover a candidate, but it cannot delete it. An executor may delete an item, but only after the item passes an independent allowlist.

The split supports three goals:

- read-only scans can run without privilege
- distribution behavior stays isolated from shared cache rules
- tests can replace command execution without changing production code

## Modules

| Module | Responsibility |
| --- | --- |
| `cli` | Clap interface and command routing, split into workflow-specific modules for arguments, operations, output, and shared support |
| `tui` | Persistent Ratatui navigation with separate state/event-loop, rendering, and workflow-execution modules |
| `distro` | `os-release` parsing and package-manager actions |
| `uninstall` | Visible desktop application discovery, package ownership, and protected-package policy |
| `scanner` | Known system, user, developer, Docker, and Flatpak candidates |
| `analyze` | Read-only disk aggregation and explicit large-file candidates |
| `purge` | Discovery of old reproducible project artifacts |
| `executor` | Exact path and command validation, removal, and process execution |
| `history` | Lock-serialized JSONL operation records with bounded rotation and tolerant reads |
| `status` | Read-only Linux health information from `/proc`, `df`, and the local package database |
| `update` | GitHub release discovery, SHA-256 verification, and atomic self-replacement |

## Adding a distribution

1. Add a `DistroFamily` variant and `os-release` identifiers.
2. Define package cache paths used only for the estimate.
3. Return a typed cleanup action with fixed arguments.
4. Add the exact command to the executor allowlist.
5. Add an `os-release` fixture and test the selected adapter.
6. Add a container smoke-test entry.

Application uninstall is separate from cleanup adapters. The catalog includes explicitly installed native packages only when they own a visible desktop entry. Flatpak applications are cataloged by installation scope. Each selection uses its exact source-qualified ID, receives a package-manager transaction preview, and passes the protected-package policy before execution. TuxCleaner never turns orphan detection into an automatic removal action.

## Application uninstall invariants

- Catalog discovery is read-only and runs without privilege.
- Native applications must be explicitly installed and own a visible desktop entry.
- Selection is empty by default and non-interactive use requires an exact `--app` ID with `--yes`.
- Native removals receive a transaction preview before confirmation.
- The executor validates the source, identifier, protected-package policy, and fixed argument shape independently.
- Flatpak installation scope is preserved in both preview and execution.
- Application configuration and user data are measured where available but never removed.

## Filesystem invariants

All traversals disable symlink following. Before deletion, the executor walks every target component with `symlink_metadata` and refuses symlinks again. This second check limits both scanner mistakes and time-of-check/time-of-use surprises involving known cache paths.

Known cleanup targets and explicit CLI removal use `remove_file` and `remove_dir_all` on exact `Path` values. No user path is interpolated into a shell command.

Large personal-file removal has a separate executor action and validator. It accepts only exact regular files in non-hidden paths under the canonical home directory. Candidates must come from the current size-threshold analysis, and hidden application data remains report-only.

The interactive Analyze explorer uses the same permanent-removal action and independent path validation as `analyze --remove`. Ratatui adds per-file selection and a final confirmation, but does not bypass the executor boundary.

All Ratatui screens render before starting potentially slow discovery. Filesystem scans, application discovery, system collection, history loading, and update checks communicate results back through channels while the event loop continues drawing. Analyze additionally carries a cancellation token because traversal can be long-running. Destructive operations keep the user on their progress screen until a result arrives, so navigation cannot detach an in-flight cleanup.

Ratatui never collects a sudo password. Before an operation containing a root command, the application disables raw mode, leaves the alternate screen, and runs `sudo -v` with inherited terminal streams. It then restores Ratatui and executes root commands through `sudo -n`. This prevents the event loop from consuming password input and prevents an expired authorization timestamp from creating an invisible prompt during background execution.

## Machine-readable interfaces

The JSON structures are regular Serde models. Fields are additive within the `0.x` series. Automation should ignore unknown fields and must pass `--yes` to request destructive cleanup. Without `--yes`, `clean --json` and `uninstall --json` return inventory only. Large-file automation additionally requires one or more exact `--file` paths from the current analysis.

History writers coordinate through a separate advisory lock so rotation cannot invalidate the synchronization point. The active file rotates at 5 MiB and retains three older files. Readers hold a shared lock, preserve newest-first ordering across rotations, and skip individual malformed JSONL records. History and lock files use owner-only permissions.

The updater selects an exact target archive from GitHub release metadata, downloads its adjacent SHA-256 asset, verifies the complete archive, extracts only the `tuxcleaner` entry, and atomically replaces the current executable. `update --check` and `update --dry-run` stop before downloading or replacing the binary.
